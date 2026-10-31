import type { DatabaseSync } from 'node:sqlite';
import type { Adapter, AdapterPayload } from 'oidc-provider';

interface ModelRow {
  payload: string;
  expires_at: number | null;
  consumed_at: number | null;
}

const now = () => Math.floor(Date.now() / 1000);

// Storage adapter for oidc-provider (sessions, grants, codes, tokens, interactions)
// on top of the same SQLite file as the users. Follows the contract of the
// library's reference adapter: expired rows are invisible, consumed rows carry
// `consumed`, and revoking a grant removes every model issued under it.
export class SqliteAdapter implements Adapter {
  constructor(
    private readonly db: DatabaseSync,
    private readonly model: string,
  ) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    this.db
      .prepare(
        `INSERT INTO oidc_models (model, id, payload, grant_id, user_code, uid, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (model, id) DO UPDATE SET payload = excluded.payload, grant_id = excluded.grant_id,
           user_code = excluded.user_code, uid = excluded.uid, expires_at = excluded.expires_at`,
      )
      .run(
        this.model,
        id,
        JSON.stringify(payload),
        payload.grantId ?? null,
        payload.userCode ?? null,
        payload.uid ?? null,
        expiresIn ? now() + expiresIn : null,
      );
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    return this.read(this.db.prepare('SELECT payload, expires_at, consumed_at FROM oidc_models WHERE model = ? AND id = ?').get(this.model, id));
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    return this.read(this.db.prepare('SELECT payload, expires_at, consumed_at FROM oidc_models WHERE model = ? AND uid = ?').get(this.model, uid));
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    return this.read(
      this.db.prepare('SELECT payload, expires_at, consumed_at FROM oidc_models WHERE model = ? AND user_code = ?').get(this.model, userCode),
    );
  }

  async consume(id: string): Promise<void> {
    this.db.prepare('UPDATE oidc_models SET consumed_at = ? WHERE model = ? AND id = ?').run(now(), this.model, id);
  }

  async destroy(id: string): Promise<void> {
    this.db.prepare('DELETE FROM oidc_models WHERE model = ? AND id = ?').run(this.model, id);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    this.db.prepare('DELETE FROM oidc_models WHERE grant_id = ?').run(grantId);
  }

  private read(row: unknown): AdapterPayload | undefined {
    const r = row as ModelRow | undefined;
    if (!r) return undefined;
    if (r.expires_at !== null && r.expires_at <= now()) return undefined;
    const payload = JSON.parse(r.payload) as AdapterPayload;
    return r.consumed_at === null ? payload : { ...payload, consumed: r.consumed_at };
  }
}

// Expired rows are never returned, but they still take space. Call this from a
// timer; once an hour is plenty for a small team.
export function deleteExpired(db: DatabaseSync): number {
  return Number(db.prepare('DELETE FROM oidc_models WHERE expires_at IS NOT NULL AND expires_at <= ?').run(now()).changes);
}
