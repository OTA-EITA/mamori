import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { openDatabase } from './db.js';
import { SecretBox } from './secretBox.js';
import { UserStore } from './users.js';

describe('SecretBox', () => {
  it('opens what it sealed, and seals the same value differently each time', () => {
    const box = new SecretBox(randomBytes(32));
    const a = box.seal('JBSWY3DPEHPK3PXP');
    const b = box.seal('JBSWY3DPEHPK3PXP');
    expect(a).not.toBe(b);
    expect(a).not.toContain('JBSWY3DPEHPK3PXP');
    expect(box.open(a)).toBe('JBSWY3DPEHPK3PXP');
  });

  it('refuses a changed value and a value sealed with another key', () => {
    const box = new SecretBox(randomBytes(32));
    const sealed = box.seal('JBSWY3DPEHPK3PXP');
    // Flip one bit of the ciphertext, of the IV and of the tag in turn.
    const raw = Buffer.from(sealed.slice(3), 'base64url');
    for (const at of [0, 12, raw.length - 1]) {
      const changed = Buffer.from(raw);
      changed[at]! ^= 0x01;
      expect(() => box.open(`v1:${changed.toString('base64url')}`)).toThrow();
    }
    expect(() => new SecretBox(randomBytes(32)).open(sealed)).toThrow();
  });

  it('creates the key file once, readable only by its owner', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'mamori-')), 'mamori.key');
    const box = SecretBox.fromKeyFile(path);
    const key = readFileSync(path, 'utf8');
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(SecretBox.fromKeyFile(path).open(box.seal('x'))).toBe('x');
    expect(readFileSync(path, 'utf8')).toBe(key);
  });
});

describe('TOTP secrets in the user store', () => {
  it('stores them sealed and returns them opened', async () => {
    const db = openDatabase(':memory:');
    const users = new UserStore(db, new SecretBox(randomBytes(32)));
    const user = await users.create({ email: 'a@example.com', name: 'A', password: 'a-long-password' });
    users.setTotpSecret(user.id, 'JBSWY3DPEHPK3PXP');
    const raw = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(user.id) as { totp_secret: string };
    expect(raw.totp_secret.startsWith('v1:')).toBe(true);
    expect(raw.totp_secret).not.toContain('JBSWY3DPEHPK3PXP');
    expect(users.findById(user.id)!.totpSecret).toBe('JBSWY3DPEHPK3PXP');
  });

  it('seals secrets that an older version stored as plain text', async () => {
    const db = openDatabase(':memory:');
    const users = new UserStore(db, new SecretBox(randomBytes(32)));
    const user = await users.create({ email: 'a@example.com', name: 'A', password: 'a-long-password' });
    db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?').run('JBSWY3DPEHPK3PXP', user.id);
    expect(users.sealPlaintextSecrets()).toBe(1);
    expect(users.sealPlaintextSecrets()).toBe(0);
    expect(users.findById(user.id)!.totpSecret).toBe('JBSWY3DPEHPK3PXP');
  });
});
