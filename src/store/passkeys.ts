import type { DatabaseSync } from 'node:sqlite';

// Passkeys (docs/v0.2.md, "Passkeys"). Only the public key is stored; the
// private key never leaves the user's device or password manager.

export interface Passkey {
  id: string; // credential id, base64url
  userId: string;
  publicKey: Uint8Array<ArrayBuffer>;
  counter: number;
  transports: string[];
  backupEligible: boolean;
  // Synced passkeys (iCloud Keychain, Google Password Manager) are backed up.
  backedUp: boolean;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

interface Row {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string;
  backup_eligible: number;
  backed_up: number;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

const toPasskey = (r: Row): Passkey => ({
  id: r.id,
  userId: r.user_id,
  publicKey: Uint8Array.from(Buffer.from(r.public_key, 'base64url')),
  counter: r.counter,
  transports: JSON.parse(r.transports) as string[],
  backupEligible: r.backup_eligible === 1,
  backedUp: r.backed_up === 1,
  name: r.name,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
});

export class PasskeyStore {
  constructor(private readonly db: DatabaseSync) {}

  add(p: Omit<Passkey, 'createdAt' | 'lastUsedAt'>): void {
    this.db
      .prepare(
        'INSERT INTO passkeys (id, user_id, public_key, counter, transports, backup_eligible, backed_up, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      )
      .run(p.id, p.userId, Buffer.from(p.publicKey).toString('base64url'), p.counter, JSON.stringify(p.transports), p.backupEligible ? 1 : 0, p.backedUp ? 1 : 0, p.name, new Date().toISOString());
  }

  find(id: string): Passkey | undefined {
    const row = this.db.prepare('SELECT * FROM passkeys WHERE id = ?').get(id) as Row | undefined;
    return row && toPasskey(row);
  }

  listByUser(userId: string): Passkey[] {
    return (this.db.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at').all(userId) as unknown as Row[]).map(toPasskey);
  }

  recordUse(id: string, counter: number, backedUp: boolean): void {
    this.db.prepare('UPDATE passkeys SET counter = ?, backed_up = ?, last_used_at = ? WHERE id = ?').run(counter, backedUp ? 1 : 0, new Date().toISOString(), id);
  }

  // Returns false when the passkey is not the user's.
  remove(userId: string, id: string): boolean {
    return Number(this.db.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').run(id, userId).changes) > 0;
  }
}
