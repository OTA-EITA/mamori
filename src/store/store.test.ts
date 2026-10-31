import { describe, expect, it } from 'vitest';
import { openDatabase } from './db.js';
import { deleteExpired, SqliteAdapter } from './oidcAdapter.js';
import { hashPassword, verifyPassword } from './password.js';
import { UserStore } from './users.js';

describe('passwords', () => {
  it('verifies the right password and rejects others', async () => {
    const hash = await hashPassword('correct horse');
    expect(hash).toMatch(/^scrypt\$32768\$8\$1\$/);
    expect(await verifyPassword('correct horse', hash)).toBe(true);
    expect(await verifyPassword('wrong horse', hash)).toBe(false);
    expect(await verifyPassword('correct horse', 'garbage')).toBe(false);
  });

  it('salts every hash', async () => {
    expect(await hashPassword('same')).not.toBe(await hashPassword('same'));
  });
});

describe('UserStore', () => {
  it('creates users and authenticates them by email, case-insensitively', async () => {
    const users = new UserStore(openDatabase(':memory:'));
    const alice = await users.create({ email: 'alice@example.com', name: 'Alice', password: 'pw-alice' });
    expect(users.findByEmail('ALICE@example.com')?.id).toBe(alice.id);
    expect((await users.authenticate('Alice@Example.com', 'pw-alice'))?.id).toBe(alice.id);
    expect(await users.authenticate('alice@example.com', 'nope')).toBeUndefined();
    expect(await users.authenticate('nobody@example.com', 'pw-alice')).toBeUndefined();
  });

  it('rejects duplicate emails', async () => {
    const users = new UserStore(openDatabase(':memory:'));
    await users.create({ email: 'a@example.com', name: 'A', password: 'x' });
    await expect(users.create({ email: 'A@example.com', name: 'A2', password: 'y' })).rejects.toThrow();
  });

  it('refuses disabled users even with the right password', async () => {
    const users = new UserStore(openDatabase(':memory:'));
    const bob = await users.create({ email: 'bob@example.com', name: 'Bob', password: 'pw-bob' });
    users.setDisabled(bob.id, true);
    expect(await users.authenticate('bob@example.com', 'pw-bob')).toBeUndefined();
  });

  it('resets the last used TOTP counter when the secret changes', async () => {
    const users = new UserStore(openDatabase(':memory:'));
    const u = await users.create({ email: 'c@example.com', name: 'C', password: 'x' });
    users.setTotpSecret(u.id, 'JBSWY3DPEHPK3PXP');
    users.setTotpLastCounter(u.id, 42);
    expect(users.findById(u.id)?.totpLastCounter).toBe(42);
    users.setTotpSecret(u.id, 'KRSXG5A');
    expect(users.findById(u.id)?.totpLastCounter).toBeNull();
  });
});

describe('SqliteAdapter', () => {
  it('stores, finds, consumes and destroys models', async () => {
    const db = openDatabase(':memory:');
    const codes = new SqliteAdapter(db, 'AuthorizationCode');
    await codes.upsert('c1', { accountId: 'u1', grantId: 'g1' }, 60);
    expect(await codes.find('c1')).toEqual({ accountId: 'u1', grantId: 'g1' });
    await codes.consume('c1');
    expect((await codes.find('c1'))?.consumed).toBeTypeOf('number');
    await codes.destroy('c1');
    expect(await codes.find('c1')).toBeUndefined();
  });

  it('keeps models of different types apart', async () => {
    const db = openDatabase(':memory:');
    await new SqliteAdapter(db, 'Session').upsert('same-id', { accountId: 'u1' });
    expect(await new SqliteAdapter(db, 'AccessToken').find('same-id')).toBeUndefined();
  });

  it('finds interactions by uid and device codes by user code', async () => {
    const db = openDatabase(':memory:');
    await new SqliteAdapter(db, 'Session').upsert('s1', { uid: 'uid-1' });
    await new SqliteAdapter(db, 'DeviceCode').upsert('d1', { userCode: 'ABCD-EFGH' });
    expect(await new SqliteAdapter(db, 'Session').findByUid('uid-1')).toEqual({ uid: 'uid-1' });
    expect(await new SqliteAdapter(db, 'DeviceCode').findByUserCode('ABCD-EFGH')).toEqual({ userCode: 'ABCD-EFGH' });
  });

  it('revokes every model issued under a grant', async () => {
    const db = openDatabase(':memory:');
    await new SqliteAdapter(db, 'AccessToken').upsert('a1', { grantId: 'g1' }, 60);
    await new SqliteAdapter(db, 'RefreshToken').upsert('r1', { grantId: 'g1' }, 60);
    await new SqliteAdapter(db, 'AccessToken').upsert('a2', { grantId: 'g2' }, 60);
    await new SqliteAdapter(db, 'AccessToken').revokeByGrantId('g1');
    expect(await new SqliteAdapter(db, 'AccessToken').find('a1')).toBeUndefined();
    expect(await new SqliteAdapter(db, 'RefreshToken').find('r1')).toBeUndefined();
    expect(await new SqliteAdapter(db, 'AccessToken').find('a2')).toBeDefined();
  });

  it('hides and deletes expired models', async () => {
    const db = openDatabase(':memory:');
    const tokens = new SqliteAdapter(db, 'AccessToken');
    await tokens.upsert('old', { accountId: 'u1' }, 60);
    db.prepare("UPDATE oidc_models SET expires_at = 1 WHERE id = 'old'").run();
    expect(await tokens.find('old')).toBeUndefined();
    expect(deleteExpired(db)).toBe(1);
  });
});
