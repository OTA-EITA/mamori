import { appendFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';

// Audit log (docs/v0.2.md, "Audit log"). Every event is a row in audit_events
// and one JSON line written to stdout or a file, so it can be shipped to a log
// service without a plugin.

export interface AuditActor {
  type: 'user' | 'admin' | 'cli';
  id?: string;
  email?: string;
}

export interface AuditEvent {
  event: string;
  actor?: AuditActor;
  client_id?: string;
  ip?: string;
  user_agent?: string;
  [detail: string]: unknown;
}

export interface AuditRecord extends AuditEvent {
  time: string;
}

// Fields that must never reach the log, whatever the caller passes.
const NEVER_LOGGED = new Set(['password', 'code', 'codes', 'recovery_code', 'token', 'access_token', 'refresh_token', 'id_token', 'secret', 'session_id', 'jti']);

export interface AuditOptions {
  // Where the JSON lines go: "-" for stdout (default), "off", or a file path.
  output?: string;
  now?: () => Date;
  // Replaces the output, for tests.
  sink?: (line: string) => void;
}

export class AuditLog {
  private readonly now: () => Date;
  private readonly sink: (line: string) => void;

  constructor(
    private readonly db: DatabaseSync,
    opts: AuditOptions = {},
  ) {
    this.now = opts.now ?? (() => new Date());
    const output = opts.output ?? '-';
    this.sink =
      opts.sink ??
      (output === 'off' ? () => {} : output === '-' ? (line) => process.stdout.write(`${line}\n`) : (line) => appendFileSync(output, `${line}\n`));
  }

  write(event: AuditEvent): AuditRecord {
    const record: AuditRecord = { time: this.now().toISOString(), ...event };
    for (const key of Object.keys(record)) if (NEVER_LOGGED.has(key)) delete record[key];
    for (const key of Object.keys(record)) if (record[key] === undefined) delete record[key];
    this.db
      .prepare('INSERT INTO audit_events (time, event, actor_id, actor_email, data) VALUES (?, ?, ?, ?, ?)')
      .run(record.time, record.event, record.actor?.id ?? null, record.actor?.email ?? null, JSON.stringify(record));
    this.sink(JSON.stringify(record));
    return record;
  }

  // Newest first.
  list(filter: { event?: string; actorId?: string; actorEmail?: string; since?: string; until?: string; limit?: number } = {}): AuditRecord[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (filter.event) (where.push('event = ?'), args.push(filter.event));
    if (filter.actorId) (where.push('actor_id = ?'), args.push(filter.actorId));
    if (filter.actorEmail) (where.push('actor_email = ? COLLATE NOCASE'), args.push(filter.actorEmail));
    if (filter.since) (where.push('time >= ?'), args.push(filter.since));
    if (filter.until) (where.push('time < ?'), args.push(filter.until));
    args.push(filter.limit ?? 100);
    const rows = this.db
      .prepare(`SELECT data FROM audit_events ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`)
      .all(...args) as { data: string }[];
    return rows.map((r) => JSON.parse(r.data) as AuditRecord);
  }

  // Deletes rows older than the retention period and returns how many.
  purge(retentionDays: number): number {
    const cutoff = new Date(this.now().getTime() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
    return Number(this.db.prepare('DELETE FROM audit_events WHERE time < ?').run(cutoff).changes);
  }
}
