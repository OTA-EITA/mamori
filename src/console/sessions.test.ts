import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { openDatabase } from '../store/db.js';
import { SecretBox } from '../store/secretBox.js';
import { UserStore } from '../store/users.js';
import { ABSOLUTE_SECONDS, ConsoleSessions, IDLE_SECONDS } from './sessions.js';

async function setup() {
  const db = openDatabase(':memory:');
  const box = new SecretBox(randomBytes(32));
  const users = new UserStore(db, box);
  const user = await users.create({ email: 'a@example.com', name: 'A', password: 'a-long-password' });
  let t = 1_800_000_000;
  const sessions = new ConsoleSessions(db, box, () => t);
  return { db, users, user, sessions, advance: (s: number) => (t += s) };
}

describe('ConsoleSessions', () => {
  it('stores only a hash of the id', async () => {
    const { db, sessions, user } = await setup();
    const id = sessions.create(user.id, ['pwd', 'otp']);
    expect(sessions.get(id)).toMatchObject({ userId: user.id, amr: ['pwd', 'otp'], pendingTotp: null });
    const stored = JSON.stringify(db.prepare('SELECT * FROM console_sessions').all());
    expect(stored).not.toContain(id);
    expect(sessions.get('not-a-session')).toBeUndefined();
  });

  it('ends after 30 idle minutes, and after 8 hours however active', async () => {
    const { sessions, user, advance } = await setup();
    const idle = sessions.create(user.id, ['pwd']);
    advance(IDLE_SECONDS + 1);
    expect(sessions.get(idle)).toBeUndefined();

    const busy = sessions.create(user.id, ['pwd']);
    for (let s = 0; s < ABSOLUTE_SECONDS - 60; s += 20 * 60) {
      expect(sessions.get(busy)).toBeDefined();
      advance(20 * 60);
    }
    advance(120);
    expect(sessions.get(busy)).toBeUndefined();
  });

  it('keeps a pending TOTP secret sealed', async () => {
    const { db, sessions, user } = await setup();
    const id = sessions.create(user.id, ['pwd']);
    sessions.setPendingTotp(id, 'JBSWY3DPEHPK3PXP');
    expect(JSON.stringify(db.prepare('SELECT * FROM console_sessions').all())).not.toContain('JBSWY3DPEHPK3PXP');
    expect(sessions.get(id)!.pendingTotp).toBe('JBSWY3DPEHPK3PXP');
  });

  it('is ended when the user is disabled', async () => {
    const { sessions, users, user } = await setup();
    const id = sessions.create(user.id, ['pwd']);
    users.setDisabled(user.id, true);
    expect(sessions.get(id)).toBeUndefined();
  });
});
