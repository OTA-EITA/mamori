import { randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { revokeAccount } from './oidcAdapter.js';
import { hashPassword, verifyPassword } from './password.js';
import { SecretBox } from './secretBox.js';

export interface User {
  id: string;
  email: string;
  name: string;
  totpSecret: string | null;
  totpLastCounter: number | null;
  disabled: boolean;
  isAdmin: boolean;
  lastSignInAt: string | null;
  createdAt: string;
  updatedAt: string | null;
  // Set by a SCIM client for its own matching.
  externalId: string | null;
  // Deleted through SCIM: disabled and hidden from SCIM, kept for the audit log.
  deletedAt: string | null;
}

interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  totp_secret: string | null;
  totp_last_counter: number | null;
  disabled: number;
  is_admin: number;
  last_sign_in_at: string | null;
  created_at: string;
  updated_at: string | null;
  external_id: string | null;
  deleted_at: string | null;
}

function toUser(row: UserRow, box: SecretBox): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    totpSecret: row.totp_secret === null ? null : box.open(row.totp_secret),
    totpLastCounter: row.totp_last_counter,
    disabled: row.disabled === 1,
    isAdmin: row.is_admin === 1,
    lastSignInAt: row.last_sign_in_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    externalId: row.external_id,
    deletedAt: row.deleted_at,
  };
}

type ChangeListener = (userId: string) => void;

export class UserStore {
  private readonly listeners: ChangeListener[] = [];

  // Called after any change that provisioning cares about.
  onChange(listener: ChangeListener): void {
    this.listeners.push(listener);
  }

  private changed(id: string): void {
    for (const l of this.listeners) l(id);
  }

  // TOTP secrets are stored sealed with this box and opened when read.
  constructor(
    private readonly db: DatabaseSync,
    private readonly box: SecretBox,
  ) {}

  // Seals TOTP secrets written by versions that stored them as plain text.
  // Runs at every start; returns how many were sealed.
  sealPlaintextSecrets(): number {
    const rows = this.db.prepare('SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL').all() as { id: string; totp_secret: string }[];
    let sealed = 0;
    for (const row of rows) {
      if (SecretBox.isSealed(row.totp_secret)) continue;
      this.db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run(this.box.seal(row.totp_secret), row.id);
      sealed++;
    }
    return sealed;
  }

  async create(input: { email: string; name: string; password: string }): Promise<User> {
    const id = randomUUID();
    this.db
      .prepare('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, input.email, input.name, await hashPassword(input.password), new Date().toISOString());
    return this.findById(id)!;
  }

  findById(id: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    return row && toUser(row, this.box);
  }

  findByEmail(email: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
    return row && toUser(row, this.box);
  }

  // Returns the user only when the password matches and the account is enabled.
  // A dummy hash is checked for unknown emails so the response time does not
  // tell whether the account exists.
  async authenticate(email: string, password: string): Promise<User | undefined> {
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
    const ok = await verifyPassword(password, row?.password_hash ?? (await dummyHash));
    if (!row || !ok || row.disabled === 1) return undefined;
    return toUser(row, this.box);
  }

  setTotpSecret(id: string, secret: string | null): void {
    this.db.prepare('UPDATE users SET totp_secret = ?, totp_last_counter = NULL WHERE id = ?').run(secret === null ? null : this.box.seal(secret), id);
  }

  async setPassword(id: string, password: string): Promise<void> {
    this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(await hashPassword(password), id);
  }

  setLastSignIn(id: string, at: Date): void {
    this.db.prepare('UPDATE users SET last_sign_in_at = ? WHERE id = ?').run(at.toISOString(), id);
  }

  setTotpLastCounter(id: string, counter: number): void {
    this.db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, id);
  }

  // For the admin console. `query` matches the email or the name.
  list(query = ''): User[] {
    const like = `%${query.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    const rows = this.db
      .prepare("SELECT * FROM users WHERE email LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\' ORDER BY email LIMIT 500")
      .all(like, like) as unknown as UserRow[];
    return rows.map((r) => toUser(r, this.box));
  }

  // Changes the given fields. Email changes keep the id, so apps keep the same `sub`.
  updateProfile(id: string, changes: { email?: string; name?: string; externalId?: string | null }): void {
    const now = new Date().toISOString();
    if (changes.email !== undefined) this.db.prepare('UPDATE users SET email = ?, updated_at = ? WHERE id = ?').run(changes.email, now, id);
    if (changes.name !== undefined) this.db.prepare('UPDATE users SET name = ?, updated_at = ? WHERE id = ?').run(changes.name, now, id);
    if (changes.externalId !== undefined) this.db.prepare('UPDATE users SET external_id = ?, updated_at = ? WHERE id = ?').run(changes.externalId, now, id);
    if (changes.email !== undefined || changes.name !== undefined) this.changed(id);
  }

  // SCIM DELETE: disable, sign out everywhere, and hide from SCIM.
  markDeleted(id: string): void {
    this.setDisabled(id, true);
    this.db.prepare('UPDATE users SET deleted_at = ?, updated_at = ? WHERE id = ?').run(new Date().toISOString(), new Date().toISOString(), id);
    this.changed(id);
  }

  // Users that SCIM can see, matching every given field exactly
  // (email case-insensitively).
  scimList(filter: { email?: string; externalId?: string }, offset: number, limit: number): { total: number; users: User[] } {
    const where = ['deleted_at IS NULL'];
    const args: string[] = [];
    if (filter.email !== undefined) (where.push('email = ? COLLATE NOCASE'), args.push(filter.email));
    if (filter.externalId !== undefined) (where.push('external_id = ?'), args.push(filter.externalId));
    const clause = where.join(' AND ');
    const total = Number((this.db.prepare(`SELECT COUNT(*) AS n FROM users WHERE ${clause}`).get(...args) as { n: number }).n);
    const rows = this.db.prepare(`SELECT * FROM users WHERE ${clause} ORDER BY created_at, id LIMIT ? OFFSET ?`).all(...args, limit, offset) as unknown as UserRow[];
    return { total, users: rows.map((r) => toUser(r, this.box)) };
  }

  countAdmins(): number {
    return Number((this.db.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled = 0').get() as { n: number }).n);
  }

  setAdmin(id: string, isAdmin: boolean): void {
    this.db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(isAdmin ? 1 : 0, id);
  }

  // Removes TOTP, passkeys and recovery codes and signs the user out
  // everywhere. With the MFA policy "required", the next sign-in goes through
  // the setup step again.
  resetSecondFactors(id: string): void {
    this.db.exec('BEGIN');
    try {
      this.db.prepare('UPDATE users SET totp_secret = NULL, totp_last_counter = NULL WHERE id = ?').run(id);
      this.db.prepare('DELETE FROM passkeys WHERE user_id = ?').run(id);
      this.db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
      this.db.prepare('DELETE FROM console_sessions WHERE user_id = ?').run(id);
      revokeAccount(this.db, id);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  // Ends every app session and console session of the user.
  signOutEverywhere(id: string): void {
    revokeAccount(this.db, id);
    this.db.prepare('DELETE FROM console_sessions WHERE user_id = ?').run(id);
  }

  // Disabling also signs the user out of every app, not only future sign-ins.
  setDisabled(id: string, disabled: boolean): void {
    this.db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
    if (disabled) {
      revokeAccount(this.db, id);
      this.db.prepare('DELETE FROM console_sessions WHERE user_id = ?').run(id);
    }
    this.changed(id);
  }
}

// A real scrypt hash of random bytes nobody knows, so that a failed lookup costs
// the same as a wrong password.
const dummyHash = hashPassword(randomBytes(32).toString('base64url'));
