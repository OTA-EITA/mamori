import { describe, expect, it } from 'vitest';
import { buildOtpauthUri, decodeBase32, encodeBase32, generateTotpSecret } from './base32.js';

describe('decodeBase32', () => {
  const test = new Uint8Array([84, 101, 115, 116]); // "Test"

  it('accepts upper case, lower case, spaces and padding alike', () => {
    for (const input of ['KRSXG5A', 'krsxg5a=', 'KRSX G5A=', 'KRSXG5A=']) expect(decodeBase32(input)).toEqual(test);
  });

  it('decodes a well-known example secret', () => {
    // "Hello!" followed by 0xDEADBEEF
    expect(decodeBase32('JBSWY3DPEHPK3PXP')).toEqual(new Uint8Array([72, 101, 108, 108, 111, 33, 0xde, 0xad, 0xbe, 0xef]));
  });

  it('rejects characters outside the alphabet', () => {
    for (const input of ['JBSW1', 'JBSW8', 'JBSW0']) expect(decodeBase32(input)).toBeNull();
  });

  it('rejects input whose leftover bits are not zero', () => {
    expect(decodeBase32('B')).toBeNull();
    expect(decodeBase32('KRSXG5B')).toBeNull();
  });

  it('decodes the empty string to no bytes', () => {
    expect(decodeBase32('')).toEqual(new Uint8Array(0));
  });
});

describe('encodeBase32', () => {
  it('round-trips random secrets', () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(encodeBase32(decodeBase32(secret)!)).toBe(secret);
  });
});

describe('buildOtpauthUri', () => {
  it('builds the URI authenticator apps scan', () => {
    expect(buildOtpauthUri({ issuer: 'Example Co', account: 'alice@example.com', secret: 'JBSWY3DPEHPK3PXP' })).toBe(
      'otpauth://totp/Example%20Co%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example+Co&algorithm=SHA1&digits=6&period=30',
    );
  });
});
