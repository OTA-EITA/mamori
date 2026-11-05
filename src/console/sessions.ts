import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { SecretBox } from '../store/secretBox.js';

// Sessions of the account page and admin console (docs/v0.2.md, "How the
// console and account page sign in"). The cookie holds a random id; only its
// SHA-256 is stored, so a copy of the database cannot be used to take over a
// session.

export const IDLE_SECONDS = 30 * 60;
export const ABSOLUTE_SECONDS = 8 * 60 * 60;

export interface ConsoleSession {
  userId: string;
  amr: string[];
  csrf: string;
  // A TOTP secret shown to the user but not confirmed with a code yet.
  pendingTotp: string | null;
  // The WebAuthn challenge of a passkey registration in progress.
  pendingChallenge: string | null;
}

interface Row {
  user_id: string;
  amr: string;
  csrf: string;
  pending_totp: string | null;
  pending_challenge: string | null;
  created_at: number;
  last_seen_at: number;
}

const hash = (id: string) => createHash('sha256').update(id).digest('base64url');

export class ConsoleSessions {
  constructor(
    private readonly db: DatabaseSync,
    private readonly box: SecretBox,
    private readonly now: () => number,
  ) {}

  // Returns the id to put in the cookie.
  create(userId: string, amr: string[]): string {
    const id = randomBytes(32).toString('base64url');
    const t = this.now();
    this.db
      .prepare('INSERT INTO console_sessions (id_hash, user_id, amr, csrf, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(hash(id), userId, JSON.stringify(amr), randomBytes(24).toString('base64url'), t, t);
    return id;
  }

  // Returns the session and extends its idle timeout, or undefined when it does
  // not exist or has timed out.
  get(id: string | undefined): ConsoleSession | undefined {
    if (!id) return undefined;
    const row = this.db.prepare('SELECT * FROM console_sessions WHERE id_hash = ?').get(hash(id)) as Row | undefined;
    if (!row) return undefined;
    const t = this.now();
    if (t - row.last_seen_at > IDLE_SECONDS || t - row.created_at > ABSOLUTE_SECONDS) {
      this.delete(id);
      return undefined;
    }
    this.db.prepare('UPDATE console_sessions SET last_seen_at = ? WHERE id_hash = ?').run(t, hash(id));
    return {
      userId: row.user_id,
      amr: JSON.parse(row.amr) as string[],
      csrf: row.csrf,
      pendingTotp: row.pending_totp === null ? null : this.box.open(row.pending_totp),
      pendingChallenge: row.pending_challenge,
    };
  }

  setPendingTotp(id: string, secret: string | null): void {
    this.db.prepare('UPDATE console_sessions SET pending_totp = ? WHERE id_hash = ?').run(secret === null ? null : this.box.seal(secret), hash(id));
  }

  setPendingChallenge(id: string, challenge: string | null): void {
    this.db.prepare('UPDATE console_sessions SET pending_challenge = ? WHERE id_hash = ?').run(challenge, hash(id));
  }

  delete(id: string): void {
    this.db.prepare('DELETE FROM console_sessions WHERE id_hash = ?').run(hash(id));
  }

  deleteExpired(): number {
    const t = this.now();
    return Number(
      this.db.prepare('DELETE FROM console_sessions WHERE last_seen_at < ? OR created_at < ?').run(t - IDLE_SECONDS, t - ABSOLUTE_SECONDS).changes,
    );
  }
}
