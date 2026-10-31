import type { IncomingMessage } from 'node:http';
import { describe, expect, it } from 'vitest';
import { clientIp } from './clientIp.js';

const req = (remote: string, xff?: string) =>
  ({ socket: { remoteAddress: remote }, headers: xff ? { 'x-forwarded-for': xff } : {} }) as unknown as IncomingMessage;

describe('clientIp', () => {
  it('ignores X-Forwarded-For unless the proxy is trusted', () => {
    expect(clientIp(req('10.0.0.5', '203.0.113.9'), false)).toBe('10.0.0.5');
  });

  it('takes the entry the trusted proxy appended, not one the client sent', () => {
    expect(clientIp(req('10.0.0.5', '198.51.100.1, 203.0.113.9'), true)).toBe('203.0.113.9');
  });

  it('falls back to the socket address when the header is missing', () => {
    expect(clientIp(req('10.0.0.5'), true)).toBe('10.0.0.5');
  });
});
