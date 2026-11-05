import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../store/db.js';
import { SecretBox } from '../store/secretBox.js';
import { UserStore } from '../store/users.js';
import { RecoveryCodes } from './recovery.js';

async function setup() {
  const db = openDatabase(':memory:');
  const users = new UserStore(db, new SecretBox(randomBytes(32)));
  const a = await users.create({ email: 'a@example.com', name: 'A', password: 'a-long-password' });
  const b = await users.create({ email: 'b@example.com', name: 'B', password: 'b-long-password' });
  return { db, recovery: new RecoveryCodes(db), a, b };
}

describe('RecoveryCodes', () => {
  it('makes ten distinct codes without look-alike characters', async () => {
    const { recovery, a } = await setup();
    const codes = recovery.generate(a.id);
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{5}-[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{5}$/);
    expect(recovery.remaining(a.id)).toBe(10);
  });

  it('accepts each code once, as typed by a person', async () => {
    const { recovery, a } = await setup();
    const [first] = recovery.generate(a.id);
    expect(recovery.use(a.id, ` ${first!.toLowerCase().replace('-', ' ')} `)).toBe(true);
    expect(recovery.use(a.id, first!)).toBe(false);
    expect(recovery.remaining(a.id)).toBe(9);
  });

  it('does not accept another user’s code or an old code', async () => {
    const { recovery, a, b } = await setup();
    const [old] = recovery.generate(a.id);
    expect(recovery.use(b.id, old!)).toBe(false);
    recovery.generate(a.id);
    expect(recovery.use(a.id, old!)).toBe(false);
  });

  it('stores only keyed hashes', async () => {
    const { db, recovery, a } = await setup();
    const codes = recovery.generate(a.id);
    const stored = JSON.stringify(db.prepare('SELECT * FROM recovery_codes').all());
    for (const c of codes) expect(stored).not.toContain(c.replace('-', ''));
  });
});
