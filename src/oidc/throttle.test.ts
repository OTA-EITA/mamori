import { describe, expect, it } from 'vitest';
import { SignInThrottle } from './throttle.js';

function setup() {
  let t = 1_000_000;
  const throttle = new SignInThrottle(() => t);
  return { throttle, advance: (s: number) => (t += s) };
}

describe('SignInThrottle', () => {
  it('locks an IP out of one email after 10 failures', () => {
    const { throttle } = setup();
    for (let i = 0; i < 9; i++) throttle.fail('a@example.com', '203.0.113.1');
    expect(throttle.isLocked('a@example.com', '203.0.113.1')).toBe(false);
    throttle.fail('a@example.com', '203.0.113.1');
    expect(throttle.isLocked('a@example.com', '203.0.113.1')).toBe(true);
  });

  it('does not lock the same email from another IP', () => {
    const { throttle } = setup();
    for (let i = 0; i < 20; i++) throttle.fail('a@example.com', '203.0.113.1');
    expect(throttle.isLocked('a@example.com', '198.51.100.7')).toBe(false);
  });

  it('slows down an email after 5 failures from any IP, up to 30 seconds', () => {
    const { throttle } = setup();
    for (let i = 0; i < 5; i++) throttle.fail('a@example.com', `203.0.113.${i}`);
    expect(throttle.delaySeconds('a@example.com')).toBe(0);
    throttle.fail('a@example.com', '203.0.113.9');
    expect(throttle.delaySeconds('a@example.com')).toBe(1);
    throttle.fail('a@example.com', '203.0.113.9');
    expect(throttle.delaySeconds('a@example.com')).toBe(2);
    for (let i = 0; i < 10; i++) throttle.fail('a@example.com', '203.0.113.9');
    expect(throttle.delaySeconds('a@example.com')).toBe(30);
  });

  it('forgets failures after 15 minutes', () => {
    const { throttle, advance } = setup();
    for (let i = 0; i < 10; i++) throttle.fail('a@example.com', '203.0.113.1');
    advance(15 * 60);
    expect(throttle.isLocked('a@example.com', '203.0.113.1')).toBe(false);
    expect(throttle.delaySeconds('a@example.com')).toBe(0);
  });

  it('clears both counters after a successful sign-in', () => {
    const { throttle } = setup();
    for (let i = 0; i < 8; i++) throttle.fail('a@example.com', '203.0.113.1');
    throttle.succeed('a@example.com', '203.0.113.1');
    expect(throttle.delaySeconds('a@example.com')).toBe(0);
  });
});
