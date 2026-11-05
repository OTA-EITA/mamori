import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import { openDatabase, SCHEMA_VERSION } from './db.js';
import { revokeAccount, SqliteAdapter } from './oidcAdapter.js';
import { UserStore } from './users.js';
import { SecretBox } from './secretBox.js';
import { randomBytes } from 'node:crypto';

const testBox = new SecretBox(randomBytes(32));

const dirs: string[] = [];
const tempDb = () => {
  const dir = mkdtempSync(join(tmpdir(), 'mamori-'));
  dirs.push(dir);
  return join(dir, 'test.db');
};
afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

// The schema v0.1 created, without a version number.
const V01_SCHEMA = `
CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL,
  password_hash TEXT NOT NULL, totp_secret TEXT, totp_last_counter INTEGER, disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE oidc_models (model TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, grant_id TEXT,
  user_code TEXT, uid TEXT, expires_at INTEGER, consumed_at INTEGER, PRIMARY KEY (model, id));
`;

describe('migrations', () => {
  it('creates a new database at the latest version', () => {
    const db = openDatabase(':memory:');
    expect((db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version).toBe(SCHEMA_VERSION);
    expect(db.prepare("SELECT value FROM settings WHERE key = 'created_by'").get()).toEqual({ value: 'v0.2' });
  });

  it('upgrades a v0.1 database and keeps its data', () => {
    const path = tempDb();
    const old = new DatabaseSync(path);
    old.exec(V01_SCHEMA);
    old.prepare("INSERT INTO users VALUES ('u1', 'a@example.com', 'A', 'x', NULL, NULL, 0, '2026-10-31')").run();
    old.prepare(`INSERT INTO oidc_models (model, id, payload) VALUES ('Session', 's1', '{"accountId":"u1"}')`).run();
    old.close();

    const db = openDatabase(path);
    expect(new UserStore(db, testBox).findById('u1')?.email).toBe('a@example.com');
    expect(db.prepare("SELECT account_id FROM oidc_models WHERE id = 's1'").get()).toEqual({ account_id: 'u1' });
    expect(db.prepare("SELECT value FROM settings WHERE key = 'created_by'").get()).toEqual({ value: 'v0.1' });
  });

  it('refuses a database from a newer mamori', () => {
    const path = tempDb();
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`);
    db.close();
    expect(() => openDatabase(path)).toThrow(/newer than this mamori/);
  });

  it('is a no-op when opened again', () => {
    const path = tempDb();
    openDatabase(path).close();
    expect(() => openDatabase(path).close()).not.toThrow();
  });
});

describe('revoking an account', () => {
  it('removes the sessions, grants and tokens of one user only', async () => {
    const db = openDatabase(':memory:');
    await new SqliteAdapter(db, 'Session').upsert('s1', { accountId: 'u1' });
    await new SqliteAdapter(db, 'Grant').upsert('g1', { accountId: 'u1' });
    await new SqliteAdapter(db, 'RefreshToken').upsert('r1', { accountId: 'u1', grantId: 'g1' }, 600);
    await new SqliteAdapter(db, 'Session').upsert('s2', { accountId: 'u2' });
    expect(revokeAccount(db, 'u1')).toBe(3);
    expect(await new SqliteAdapter(db, 'Session').find('s2')).toBeDefined();
  });

  it('happens when a user is disabled', async () => {
    const db = openDatabase(':memory:');
    const users = new UserStore(db, testBox);
    const u = await users.create({ email: 'b@example.com', name: 'B', password: 'pw' });
    await new SqliteAdapter(db, 'Session').upsert('s1', { accountId: u.id });
    users.setDisabled(u.id, true);
    expect(await new SqliteAdapter(db, 'Session').find('s1')).toBeUndefined();
  });
});
