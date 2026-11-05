import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';

// Encryption for values the server must read back, such as TOTP secrets, which
// cannot be hashed like passwords. The key lives in a file outside the SQLite
// database, so a copy of the database alone does not reveal the secrets.
//
// Format: "v1:" + base64url(12-byte IV || ciphertext || 16-byte GCM tag).

const PREFIX = 'v1:';

export class SecretBox {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error('the encryption key must be 32 bytes');
  }

  // Reads the key file, or creates it with a new random key (mode 0600).
  static fromKeyFile(path: string): SecretBox {
    if (!existsSync(path)) {
      writeFileSync(path, `${randomBytes(32).toString('base64url')}\n`, { mode: 0o600, flag: 'wx' });
      chmodSync(path, 0o600);
    }
    return new SecretBox(Buffer.from(readFileSync(path, 'utf8').trim(), 'base64url'));
  }

  static isSealed(value: string): boolean {
    return value.startsWith(PREFIX);
  }

  seal(plaintext: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return PREFIX + Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64url');
  }

  // Throws when the value was changed or sealed with another key.
  open(sealed: string): string {
    if (!SecretBox.isSealed(sealed)) throw new Error('not a sealed value');
    const raw = Buffer.from(sealed.slice(PREFIX.length), 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', this.key, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString('utf8');
  }
}
