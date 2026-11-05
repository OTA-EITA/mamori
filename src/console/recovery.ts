import { createHmac, randomBytes, randomInt } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

// Recovery codes (docs/v0.2.md, "Recovery codes"): ten codes of 10 characters
// from an alphabet without look-alike characters (31 symbols, about 49.5 bits
// each), shown once. They are stored as HMAC-SHA256 with a server key, not
// scrypt: checking means comparing against up to ten hashes, and the entropy
// of the codes plus the sign-in throttling make a fast hash enough.

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const LENGTH = 10;
const COUNT = 10;

function newCode(): string {
  let code = '';
  for (let i = 0; i < LENGTH; i++) code += ALPHABET[randomInt(ALPHABET.length)];
  return code;
}

// What people type: lower case, spaces and the hyphen in the middle are fine.
export function normalizeRecoveryCode(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '');
}

export function looksLikeRecoveryCode(input: string): boolean {
  return new RegExp(`^[${ALPHABET}]{${LENGTH}}$`).test(normalizeRecoveryCode(input));
}

export class RecoveryCodes {
  private readonly key: Buffer;

  constructor(private readonly db: DatabaseSync) {
    db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run('recovery_code_key', randomBytes(32).toString('base64url'));
    const row = db.prepare("SELECT value FROM settings WHERE key = 'recovery_code_key'").get() as { value: string };
    this.key = Buffer.from(row.value, 'base64url');
  }

  private hash(code: string): string {
    return createHmac('sha256', this.key).update(normalizeRecoveryCode(code)).digest('base64url');
  }

  // Replaces any earlier codes and returns the new ones, formatted XXXXX-XXXXX.
  generate(userId: string): string[] {
    const codes = Array.from({ length: COUNT }, newCode);
    this.db.exec('BEGIN');
    try {
      this.db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
      const insert = this.db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
      for (const code of codes) insert.run(userId, this.hash(code));
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    return codes.map((c) => `${c.slice(0, 5)}-${c.slice(5)}`);
  }

  remaining(userId: string): number {
    return Number((this.db.prepare('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId) as { n: number }).n);
  }

  // Marks the code used and returns true, or returns false when it is not one
  // of the user's unused codes. Each code works once.
  use(userId: string, input: string): boolean {
    if (!looksLikeRecoveryCode(input)) return false;
    const changes = this.db
      .prepare('UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
      .run(new Date().toISOString(), userId, this.hash(input)).changes;
    return Number(changes) > 0;
  }
}
