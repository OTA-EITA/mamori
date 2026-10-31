import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

// Signing keys and cookie keys are created on first start and kept in the
// database, so restarting the server does not log everybody out or invalidate
// issued ID tokens.

function getOrCreate(db: DatabaseSync, key: string, create: () => string): string {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as { value: string } | undefined;
  if (row) return row.value;
  const value = create();
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(key, value);
  return value;
}

export function signingJwks(db: DatabaseSync): { keys: object[] } {
  return JSON.parse(
    getOrCreate(db, 'jwks', () => {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), alg: 'RS256', use: 'sig' };
      return JSON.stringify({ keys: [jwk] });
    }),
  );
}

export function cookieKeys(db: DatabaseSync): string[] {
  return JSON.parse(getOrCreate(db, 'cookie_keys', () => JSON.stringify([randomBytes(32).toString('base64url')])));
}
