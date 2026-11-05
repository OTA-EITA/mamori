import { randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { revokeAccount } from './oidcAdapter.js';
import { hashPassword, verifyPassword } from './password.js';

export interface User {
  id: string;
  email: string;
  name: string;
  totpSecret: string | null;
  totpLastCounter: number | null;
  disabled: boolean;
  isAdmin: boolean;
  lastSignInAt: string | null;
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
}

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    totpSecret: row.totp_secret,
    totpLastCounter: row.totp_last_counter,
    disabled: row.disabled === 1,
    isAdmin: row.is_admin === 1,
    lastSignInAt: row.last_sign_in_at,
  };
}

export class UserStore {
  constructor(private readonly db: DatabaseSync) {}

  async create(input: { email: string; name: string; password: string }): Promise<User> {
    const id = randomUUID();
    this.db
      .prepare('INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, input.email, input.name, await hashPassword(input.password), new Date().toISOString());
    return this.findById(id)!;
  }

  findById(id: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    return row && toUser(row);
  }

  findByEmail(email: string): User | undefined {
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
    return row && toUser(row);
  }

  // Returns the user only when the password matches and the account is enabled.
  // A dummy hash is checked for unknown emails so the response time does not
  // tell whether the account exists.
  async authenticate(email: string, password: string): Promise<User | undefined> {
    const row = this.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
    const ok = await verifyPassword(password, row?.password_hash ?? (await dummyHash));
    if (!row || !ok || row.disabled === 1) return undefined;
    return toUser(row);
  }

  setTotpSecret(id: string, secret: string | null): void {
    this.db.prepare('UPDATE users SET totp_secret = ?, totp_last_counter = NULL WHERE id = ?').run(secret, id);
  }

  setLastSignIn(id: string, at: Date): void {
    this.db.prepare('UPDATE users SET last_sign_in_at = ? WHERE id = ?').run(at.toISOString(), id);
  }

  setTotpLastCounter(id: string, counter: number): void {
    this.db.prepare('UPDATE users SET totp_last_counter = ? WHERE id = ?').run(counter, id);
  }

  // Disabling also signs the user out of every app, not only future sign-ins.
  setDisabled(id: string, disabled: boolean): void {
    this.db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
    if (disabled) revokeAccount(this.db, id);
  }
}

// A real scrypt hash of random bytes nobody knows, so that a failed lookup costs
// the same as a wrong password.
const dummyHash = hashPassword(randomBytes(32).toString('base64url'));
