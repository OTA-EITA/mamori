import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

// Setup links (docs/v0.2.md, "Creating users from the console"). An admin
// creates one and passes it to the person over chat; it lets them choose a
// password once, within 24 hours. Only a hash of the token is stored.

export const SETUP_LINK_SECONDS = 24 * 60 * 60;

const hash = (token: string) => createHash('sha256').update(token).digest('base64url');

export class SetupLinks {
  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number,
  ) {}

  // Returns the token for the URL. Earlier links of the user stop working.
  create(userId: string): string {
    const token = randomBytes(32).toString('base64url');
    this.db.prepare('DELETE FROM setup_links WHERE user_id = ?').run(userId);
    this.db.prepare('INSERT INTO setup_links (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(hash(token), userId, this.now() + SETUP_LINK_SECONDS);
    return token;
  }

  // The user id when the link can still be used.
  check(token: string): string | undefined {
    const row = this.db.prepare('SELECT user_id, expires_at, used_at FROM setup_links WHERE token_hash = ?').get(hash(token)) as
      | { user_id: string; expires_at: number; used_at: number | null }
      | undefined;
    if (!row || row.used_at !== null || row.expires_at <= this.now()) return undefined;
    return row.user_id;
  }

  // Marks the link used; false when someone used it first.
  use(token: string): boolean {
    return Number(this.db.prepare('UPDATE setup_links SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?').run(this.now(), hash(token), this.now()).changes) > 0;
  }
}
