import { describe, expect, it } from 'vitest';
import { openDatabase } from '../store/db.js';
import { AuditLog } from './audit.js';

function setup(start = '2026-11-05T00:00:00.000Z') {
  const db = openDatabase(':memory:');
  const lines: string[] = [];
  let now = new Date(start);
  const audit = new AuditLog(db, { sink: (line) => lines.push(line), now: () => now });
  return { audit, lines, setNow: (iso: string) => (now = new Date(iso)) };
}

describe('AuditLog', () => {
  it('stores the event and writes the same JSON line', () => {
    const { audit, lines } = setup();
    audit.write({ event: 'sign_in.failed', actor: { type: 'user', email: 'alice@example.com' }, ip: '203.0.113.9', reason: 'wrong_password' });
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toEqual({
      time: '2026-11-05T00:00:00.000Z',
      event: 'sign_in.failed',
      actor: { type: 'user', email: 'alice@example.com' },
      ip: '203.0.113.9',
      reason: 'wrong_password',
    });
    expect(audit.list()).toEqual([JSON.parse(lines[0]!)]);
  });

  it('never keeps secrets, even when a caller passes them', () => {
    const { audit, lines } = setup();
    audit.write({ event: 'sign_in.failed', password: 'hunter2hunter2', code: '123456', access_token: 'abc', jti: 'xyz' });
    expect(lines[0]).not.toMatch(/hunter2|123456|abc|xyz/);
    expect(JSON.stringify(audit.list())).not.toMatch(/hunter2|123456|abc|xyz/);
  });

  it('filters by event, actor and time, newest first', () => {
    const { audit, setNow } = setup();
    audit.write({ event: 'sign_in.succeeded', actor: { type: 'user', id: 'u1' } });
    setNow('2026-11-05T01:00:00.000Z');
    audit.write({ event: 'sign_in.failed', actor: { type: 'user', id: 'u1' } });
    setNow('2026-11-05T02:00:00.000Z');
    audit.write({ event: 'sign_in.succeeded', actor: { type: 'user', id: 'u2' } });

    expect(audit.list().map((e) => e.time)).toEqual(['2026-11-05T02:00:00.000Z', '2026-11-05T01:00:00.000Z', '2026-11-05T00:00:00.000Z']);
    expect(audit.list({ event: 'sign_in.succeeded' })).toHaveLength(2);
    expect(audit.list({ actorId: 'u1' })).toHaveLength(2);
    expect(audit.list({ since: '2026-11-05T01:00:00.000Z', until: '2026-11-05T02:00:00.000Z' }).map((e) => e.event)).toEqual(['sign_in.failed']);
    expect(audit.list({ limit: 1 })).toHaveLength(1);
  });

  it('deletes rows older than the retention period', () => {
    const { audit, setNow } = setup('2025-01-01T00:00:00.000Z');
    audit.write({ event: 'old' });
    setNow('2026-11-05T00:00:00.000Z');
    audit.write({ event: 'new' });
    expect(audit.purge(400)).toBe(1);
    expect(audit.list().map((e) => e.event)).toEqual(['new']);
  });
});
