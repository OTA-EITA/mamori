import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../store/db.js';
import { SecretBox } from '../store/secretBox.js';
import { UserStore } from '../store/users.js';
import { SETUP_LINK_SECONDS, SetupLinks } from './setupLinks.js';

async function setup() {
  const db = openDatabase(':memory:');
  const users = new UserStore(db, new SecretBox(randomBytes(32)));
  const user = await users.create({ email: 'a@example.com', name: 'A', password: 'a-long-password' });
  let t = 1_800_000_000;
  return { db, users, user, links: new SetupLinks(db, () => t), advance: (s: number) => (t += s) };
}

describe('SetupLinks', () => {
  it('works once', async () => {
    const { links, user } = await setup();
    const token = links.create(user.id);
    expect(links.check(token)).toBe(user.id);
    expect(links.use(token)).toBe(true);
    expect(links.use(token)).toBe(false);
    expect(links.check(token)).toBeUndefined();
  });

  it('stops working after 24 hours', async () => {
    const { links, user, advance } = await setup();
    const token = links.create(user.id);
    advance(SETUP_LINK_SECONDS);
    expect(links.check(token)).toBeUndefined();
    expect(links.use(token)).toBe(false);
  });

  it('replaces earlier links and stores only hashes', async () => {
    const { db, links, user } = await setup();
    const old = links.create(user.id);
    const fresh = links.create(user.id);
    expect(links.check(old)).toBeUndefined();
    expect(links.check(fresh)).toBe(user.id);
    expect(JSON.stringify(db.prepare('SELECT * FROM setup_links').all())).not.toContain(fresh);
  });
});

describe('UserStore.list', () => {
  it('searches email and name, treating % and _ as plain characters', async () => {
    const { users } = await setup();
    await users.create({ email: 'b_c@example.com', name: 'Bob', password: 'b-long-password' });
    expect(users.list('bob').map((u) => u.email)).toEqual(['b_c@example.com']);
    expect(users.list('b_c').map((u) => u.email)).toEqual(['b_c@example.com']);
    expect(users.list('%').map((u) => u.email)).toEqual([]);
    expect(users.list('').length).toBe(2);
  });
});
