import type { DatabaseSync } from 'node:sqlite';
import type { AuditLog } from '../audit/audit.js';
import type { GroupStore } from '../store/groups.js';
import type { User, UserStore } from '../store/users.js';
import { RetryLaterError, type Connector, type ExternalAccount } from './connector.js';

// Outbound provisioning (docs/v0.3.md). Changes in mamori queue a job per
// connector and user; the worker brings that user's account at the SaaS in line
// with mamori: active members of the connector's group have an active account,
// everyone else who had one is suspended. Nothing is ever deleted.

const MAX_DELAY_SECONDS = 60 * 60;
const GIVE_UP_SECONDS = 24 * 60 * 60;

export type Plan = { action: 'create' | 'reactivate' | 'update' | 'suspend' | 'none'; reason: string };

interface Link {
  external_id: string;
  state: 'active' | 'suspended';
}

export interface JobView {
  connector: string;
  userId: string;
  email: string | undefined;
  attempts: number;
  lastError: string | null;
  failed: boolean;
  nextAt: number;
}

export class Provisioning {
  private readonly connectors = new Map<string, Connector>();
  private running = false;

  constructor(
    private readonly db: DatabaseSync,
    private readonly users: UserStore,
    private readonly groups: GroupStore,
    connectors: Connector[],
    private readonly now: () => number,
    private readonly audit?: AuditLog,
  ) {
    for (const c of connectors) this.connectors.set(c.name, c);
  }

  get connectorNames(): string[] {
    return [...this.connectors.keys()];
  }

  connectorGroups(): { name: string; group: string }[] {
    return [...this.connectors.values()].map((c) => ({ name: c.name, group: c.group }));
  }

  // Queues a sync of this user at every connector. Called by the stores on any
  // change that could matter: membership, enable/disable, profile, delete.
  userChanged(userId: string): void {
    const t = this.now();
    const insert = this.db.prepare('INSERT OR IGNORE INTO provisioning_jobs (connector, user_id, created_at, next_at) VALUES (?, ?, ?, ?)');
    for (const name of this.connectors.keys()) insert.run(name, userId, t, t);
  }

  private link(connector: string, userId: string): Link | undefined {
    return this.db.prepare('SELECT external_id, state FROM provisioning_links WHERE connector = ? AND user_id = ?').get(connector, userId) as Link | undefined;
  }

  private saveLink(connector: string, userId: string, externalId: string, state: Link['state']): void {
    this.db
      .prepare(
        `INSERT INTO provisioning_links (connector, user_id, external_id, state, synced_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (connector, user_id) DO UPDATE SET external_id = excluded.external_id, state = excluded.state, synced_at = excluded.synced_at`,
      )
      .run(connector, userId, externalId, state, this.now());
  }

  private shouldHaveAccount(connector: Connector, user: User): boolean {
    return !user.disabled && !user.deletedAt && this.groups.namesOf(user.id).some((g) => g.toLowerCase() === connector.group.toLowerCase());
  }

  // What would be done for this user, without doing it.
  async plan(connector: Connector, user: User): Promise<{ plan: Plan; account: ExternalAccount | undefined }> {
    const link = this.link(connector.name, user.id);
    const account = link ? await connector.get(link.external_id) : await connector.findByEmail(user.email);
    if (this.shouldHaveAccount(connector, user)) {
      if (!account) return { plan: { action: 'create', reason: 'member without an account' }, account };
      if (!account.active) return { plan: { action: 'reactivate', reason: 'member with a suspended account' }, account };
      if (account.email.toLowerCase() !== user.email.toLowerCase() || account.name !== user.name) return { plan: { action: 'update', reason: 'name or email changed' }, account };
      return { plan: { action: 'none', reason: 'in sync' }, account };
    }
    if (account?.active) return { plan: { action: 'suspend', reason: user.disabled ? 'disabled in mamori' : `not in group ${connector.group}` }, account };
    return { plan: { action: 'none', reason: 'no active account' }, account };
  }

  private async sync(connector: Connector, user: User): Promise<Plan> {
    const { plan, account } = await this.plan(connector, user);
    const person = { email: user.email, name: user.name };
    let id = account?.id;
    switch (plan.action) {
      case 'create':
        id = (await connector.create(person)).id;
        break;
      case 'reactivate':
        await connector.reactivate(id!);
        if (account!.email.toLowerCase() !== user.email.toLowerCase() || account!.name !== user.name) await connector.update(id!, person);
        break;
      case 'update':
        await connector.update(id!, person);
        break;
      case 'suspend':
        await connector.suspend(id!);
        break;
      case 'none':
        break;
    }
    if (id) {
      const active = plan.action === 'suspend' ? false : plan.action === 'none' ? account!.active : true;
      this.saveLink(connector.name, user.id, id, active ? 'active' : 'suspended');
    }
    if (plan.action !== 'none') {
      this.audit?.write({ event: `provisioning.${plan.action}`, actor: { type: 'system' }, connector: connector.name, user_id: user.id, user_email: user.email, reason: plan.reason });
    }
    return plan;
  }

  // Runs the jobs that are due. Returns how many ran.
  async runDue(limit = 50): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      const jobs = this.db
        .prepare('SELECT id, connector, user_id, created_at, attempts FROM provisioning_jobs WHERE done_at IS NULL AND next_at <= ? ORDER BY next_at LIMIT ?')
        .all(this.now(), limit) as { id: number; connector: string; user_id: string; created_at: number; attempts: number }[];
      for (const job of jobs) {
        const connector = this.connectors.get(job.connector);
        const user = this.users.findById(job.user_id);
        if (!connector || !user) {
          this.db.prepare('UPDATE provisioning_jobs SET done_at = ? WHERE id = ?').run(this.now(), job.id);
          continue;
        }
        // Mark it done first: a change made while it runs queues a new job.
        this.db.prepare('UPDATE provisioning_jobs SET done_at = ? WHERE id = ?').run(this.now(), job.id);
        try {
          await this.sync(connector, user);
        } catch (err) {
          const attempts = job.attempts + 1;
          const message = err instanceof Error ? err.message : String(err);
          const delay = err instanceof RetryLaterError ? err.seconds : Math.min(30 * 2 ** (attempts - 1), MAX_DELAY_SECONDS);
          const giveUp = this.now() + delay - job.created_at > GIVE_UP_SECONDS;
          // Put it back as pending, unless a newer job for the same user exists.
          this.db
            .prepare(
              `UPDATE provisioning_jobs SET done_at = ?, attempts = ?, last_error = ?, next_at = ?, failed = ?
               WHERE id = ? AND NOT EXISTS (SELECT 1 FROM provisioning_jobs WHERE connector = ? AND user_id = ? AND done_at IS NULL AND id != ?)`,
            )
            .run(giveUp ? this.now() : null, attempts, message.slice(0, 500), this.now() + delay, giveUp ? 1 : 0, job.id, job.connector, job.user_id, job.id);
          if (giveUp) this.audit?.write({ event: 'provisioning.failed', actor: { type: 'system' }, connector: connector.name, user_id: user.id, user_email: user.email, reason: message.slice(0, 200) });
        }
      }
      return jobs.length;
    } finally {
      this.running = false;
    }
  }

  // Pending and failed jobs, for the admin console.
  jobs(): JobView[] {
    const rows = this.db
      .prepare('SELECT connector, user_id, attempts, last_error, failed, next_at FROM provisioning_jobs WHERE done_at IS NULL OR failed = 1 ORDER BY id DESC LIMIT 200')
      .all() as { connector: string; user_id: string; attempts: number; last_error: string | null; failed: number; next_at: number }[];
    return rows.map((r) => ({
      connector: r.connector,
      userId: r.user_id,
      email: this.users.findById(r.user_id)?.email,
      attempts: r.attempts,
      lastError: r.last_error,
      failed: r.failed === 1,
      nextAt: r.next_at,
    }));
  }

  // Compares mamori with the SaaS for everyone who is, or was, provisioned
  // there, and queues the differences when `apply` is true.
  async reconcile(name: string, apply: boolean): Promise<{ email: string; plan: Plan }[]> {
    const connector = this.connectors.get(name);
    if (!connector) throw new Error(`no connector ${name}`);
    const group = this.groups.findByName(connector.group);
    const ids = new Set<string>(group ? this.groups.members(group.id).map((m) => m.id) : []);
    for (const r of this.db.prepare('SELECT user_id FROM provisioning_links WHERE connector = ?').all(name) as { user_id: string }[]) ids.add(r.user_id);
    const out: { email: string; plan: Plan }[] = [];
    for (const id of ids) {
      const user = this.users.findById(id);
      if (!user) continue;
      const { plan } = await this.plan(connector, user);
      if (plan.action === 'none') continue;
      out.push({ email: user.email, plan });
      if (apply) this.userChanged(user.id);
    }
    return out;
  }

  // Runs due jobs every `seconds`. Returns a function that stops it.
  start(seconds = 15): () => void {
    const timer = setInterval(() => void this.runDue().catch(() => {}), seconds * 1000);
    timer.unref();
    return () => clearInterval(timer);
  }
}
