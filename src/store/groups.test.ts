import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openDatabase } from './db.js';
import { GroupStore } from './groups.js';
import { SecretBox } from './secretBox.js';
import { UserStore } from './users.js';

async function setup() {
  const db = openDatabase(':memory:');
  const users = new UserStore(db, new SecretBox(randomBytes(32)));
  const alice = await users.create({ email: 'alice@example.com', name: 'Alice', password: 'alice-password-1' });
  return { db, users, groups: new GroupStore(db), alice };
}

describe('GroupStore', () => {
  it('lists a user’s groups by name, sorted', async () => {
    const { groups, alice } = await setup();
    const eng = groups.create('engineering', 'Developers');
    const all = groups.create('all-staff');
    groups.create('sales');
    expect(groups.addMember(eng.id, alice.id)).toBe(true);
    expect(groups.addMember(eng.id, alice.id)).toBe(false);
    groups.addMember(all.id, alice.id);
    expect(groups.namesOf(alice.id)).toEqual(['all-staff', 'engineering']);
    expect(groups.members(eng.id).map((m) => m.email)).toEqual(['alice@example.com']);
    expect(groups.removeMember(eng.id, alice.id)).toBe(true);
    expect(groups.removeMember(eng.id, alice.id)).toBe(false);
    expect(groups.namesOf(alice.id)).toEqual(['all-staff']);
  });

  it('refuses names that apps would have trouble matching', async () => {
    const { groups } = await setup();
    expect(() => groups.create('has space')).toThrow();
    expect(() => groups.create('')).toThrow();
    expect(() => groups.create('-leading-hyphen')).toThrow();
    groups.create('Engineering');
    expect(() => groups.create('engineering')).toThrow();
  });

  it('drops memberships when the user is deleted', async () => {
    const { db, groups, alice } = await setup();
    const eng = groups.create('engineering');
    groups.addMember(eng.id, alice.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(alice.id);
    expect(groups.members(eng.id)).toEqual([]);
  });
});
