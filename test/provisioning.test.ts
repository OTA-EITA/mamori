import { randomBytes, randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AuditLog, type AuditRecord } from '../src/audit/audit.js';
import { RetryLaterError, type Connector, type ExternalAccount, type Person } from '../src/provisioning/connector.js';
import { Provisioning } from '../src/provisioning/engine.js';
import { openDatabase } from '../src/store/db.js';
import { GroupStore } from '../src/store/groups.js';
import { SecretBox } from '../src/store/secretBox.js';
import { UserStore } from '../src/store/users.js';

// An in-memory SaaS. It has no delete, like the real connectors.
class FakeSaas implements Connector {
  readonly accounts = new Map<string, ExternalAccount>();
  readonly calls: string[] = [];
  failNext: Error[] = [];
  constructor(
    readonly name: string,
    readonly group: string,
  ) {}
  private maybeFail() {
    const err = this.failNext.shift();
    if (err) throw err;
  }
  async findByEmail(email: string) {
    this.maybeFail();
    return [...this.accounts.values()].find((a) => a.email.toLowerCase() === email.toLowerCase());
  }
  async get(id: string) {
    this.maybeFail();
    return this.accounts.get(id);
  }
  async create(p: Person) {
    this.maybeFail();
    const a = { id: randomUUID(), email: p.email, name: p.name, active: true };
    this.accounts.set(a.id, a);
    this.calls.push(`create ${p.email}`);
    return { ...a };
  }
  async update(id: string, p: Person) {
    this.maybeFail();
    Object.assign(this.accounts.get(id)!, { email: p.email, name: p.name });
    this.calls.push(`update ${p.email}`);
  }
  async suspend(id: string) {
    this.maybeFail();
    this.accounts.get(id)!.active = false;
    this.calls.push(`suspend ${this.accounts.get(id)!.email}`);
  }
  async reactivate(id: string) {
    this.maybeFail();
    this.accounts.get(id)!.active = true;
    this.calls.push(`reactivate ${this.accounts.get(id)!.email}`);
  }
}

async function setup() {
  const db = openDatabase(':memory:');
  const users = new UserStore(db, new SecretBox(randomBytes(32)));
  const groups = new GroupStore(db);
  const saas = new FakeSaas('slack', 'slack-users');
  let t = 1_800_000_000;
  const lines: string[] = [];
  const audit = new AuditLog(db, { sink: (l) => lines.push(l), now: () => new Date(t * 1000) });
  const prov = new Provisioning(db, users, groups, [saas], () => t, audit);
  users.onChange((id) => prov.userChanged(id));
  groups.onMembershipChange((id) => prov.userChanged(id));
  const group = groups.create('slack-users');
  const alice = await users.create({ email: 'alice@example.co.jp', name: 'Alice', password: 'alice-password-1' });
  return { db, users, groups, saas, prov, group, alice, events: () => lines.map((l) => JSON.parse(l) as AuditRecord), advance: (s: number) => (t += s) };
}

describe('outbound provisioning', () => {
  it('creates an account when someone joins the group, and follows disable and enable', async () => {
    const { users, groups, saas, prov, group, alice } = await setup();
    expect(await prov.runDue()).toBe(0);
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    expect(saas.calls).toEqual(['create alice@example.co.jp']);

    users.setDisabled(alice.id, true);
    await prov.runDue();
    users.setDisabled(alice.id, false);
    await prov.runDue();
    expect(saas.calls).toEqual(['create alice@example.co.jp', 'suspend alice@example.co.jp', 'reactivate alice@example.co.jp']);
    expect(saas.accounts.size).toBe(1);
  });

  it('suspends when someone leaves the group, and never deletes', async () => {
    const { groups, saas, prov, group, alice } = await setup();
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    groups.removeMember(group.id, alice.id);
    await prov.runDue();
    expect([...saas.accounts.values()]).toMatchObject([{ email: 'alice@example.co.jp', active: false }]);
  });

  it('updates the name and email, keeping the same account', async () => {
    const { users, groups, saas, prov, group, alice } = await setup();
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    users.updateProfile(alice.id, { name: 'Alice Suzuki', email: 'alice.suzuki@example.co.jp' });
    await prov.runDue();
    expect([...saas.accounts.values()]).toMatchObject([{ email: 'alice.suzuki@example.co.jp', name: 'Alice Suzuki', active: true }]);
  });

  it('takes over an account that already exists at the SaaS instead of making a second one', async () => {
    const { groups, saas, prov, group, alice } = await setup();
    saas.accounts.set('pre', { id: 'pre', email: 'ALICE@example.co.jp', name: 'Alice', active: false });
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    // Email addresses match regardless of case, so only reactivation is needed.
    expect(saas.calls).toEqual(['reactivate ALICE@example.co.jp']);
    expect(saas.accounts.size).toBe(1);
  });

  it('collapses repeated changes into one job', async () => {
    const { users, groups, saas, prov, group, alice } = await setup();
    groups.addMember(group.id, alice.id);
    users.updateProfile(alice.id, { name: 'A' });
    users.updateProfile(alice.id, { name: 'Alice' });
    expect(await prov.runDue()).toBe(1);
    expect(saas.calls).toEqual(['create alice@example.co.jp']);
  });

  it('retries with backoff, waits as long as a 429 asks, and gives up after a day', async () => {
    const { users, groups, saas, prov, group, alice, advance, events } = await setup();
    saas.failNext = [new Error('connection reset')];
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    expect(prov.jobs()).toMatchObject([{ attempts: 1, lastError: 'connection reset', failed: false }]);
    // Not due yet; then due after the 30 s backoff.
    expect(await prov.runDue()).toBe(0);
    saas.failNext = [new RetryLaterError(120)];
    advance(30);
    await prov.runDue();
    advance(60);
    expect(await prov.runDue()).toBe(0);
    advance(60);
    await prov.runDue();
    expect(saas.calls).toEqual(['create alice@example.co.jp']);
    expect(prov.jobs()).toEqual([]);

    const bob = await users.create({ email: 'bob@example.co.jp', name: 'Bob', password: 'bob-password-12' });
    for (let i = 0; i < 40; i++) saas.failNext.push(new Error('still down'));
    groups.addMember(group.id, bob.id);
    for (let h = 0; h < 26; h++) {
      await prov.runDue();
      advance(60 * 60);
    }
    expect(prov.jobs()).toMatchObject([{ email: 'bob@example.co.jp', failed: true, lastError: 'still down' }]);
    expect(events().some((e) => e.event === 'provisioning.failed' && e.user_email === 'bob@example.co.jp')).toBe(true);
  });

  it('reconciles changes made by hand at the SaaS', async () => {
    const { users, groups, saas, prov, group, alice } = await setup();
    groups.addMember(group.id, alice.id);
    await prov.runDue();
    users.setDisabled(alice.id, true);
    await prov.runDue();
    // Someone reactivates the leaver directly in the SaaS.
    [...saas.accounts.values()][0]!.active = true;
    expect(await prov.reconcile('slack', false)).toEqual([{ email: 'alice@example.co.jp', plan: { action: 'suspend', reason: 'disabled in mamori' } }]);
    expect(await prov.runDue()).toBe(0);
    await prov.reconcile('slack', true);
    await prov.runDue();
    expect([...saas.accounts.values()][0]!.active).toBe(false);
    expect(await prov.reconcile('slack', false)).toEqual([]);
  });
});
