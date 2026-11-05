import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

// Bearer tokens for the SCIM API. Shown once when created; only a SHA-256 is
// stored. The prefix makes a leaked token easy to recognise in a scanner.

const PREFIX = 'mamori_scim_';
const hash = (token: string) => createHash('sha256').update(token).digest('base64url');

export interface ScimToken {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export class ScimTokens {
  constructor(private readonly db: DatabaseSync) {}

  create(name: string): { token: string; id: string } {
    const token = PREFIX + randomBytes(32).toString('base64url');
    const id = randomUUID();
    this.db.prepare('INSERT INTO scim_tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)').run(id, name, hash(token), new Date().toISOString());
    return { token, id };
  }

  // The token's name when it is valid, and records the use.
  verify(token: string): ScimToken | undefined {
    if (!token.startsWith(PREFIX)) return undefined;
    const row = this.db.prepare('SELECT id, name, created_at, last_used_at FROM scim_tokens WHERE token_hash = ?').get(hash(token)) as
      | { id: string; name: string; created_at: string; last_used_at: string | null }
      | undefined;
    if (!row) return undefined;
    this.db.prepare('UPDATE scim_tokens SET last_used_at = ? WHERE id = ?').run(new Date().toISOString(), row.id);
    return { id: row.id, name: row.name, createdAt: row.created_at, lastUsedAt: row.last_used_at };
  }

  list(): ScimToken[] {
    return (this.db.prepare('SELECT id, name, created_at, last_used_at FROM scim_tokens ORDER BY created_at').all() as { id: string; name: string; created_at: string; last_used_at: string | null }[]).map(
      (r) => ({ id: r.id, name: r.name, createdAt: r.created_at, lastUsedAt: r.last_used_at }),
    );
  }

  revoke(id: string): boolean {
    return Number(this.db.prepare('DELETE FROM scim_tokens WHERE id = ?').run(id).changes) > 0;
  }
}
