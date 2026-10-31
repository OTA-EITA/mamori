import { describe, expect, it } from 'vitest';
import { generateTotp, verifyTotp, type TotpAlgorithm } from './totp.js';

// RFC 6238 appendix B. Each algorithm uses a key of its own hash length.
const SECRETS: Record<TotpAlgorithm, Uint8Array> = {
  SHA1: new TextEncoder().encode('12345678901234567890'),
  SHA256: new TextEncoder().encode('12345678901234567890123456789012'),
  SHA512: new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234'),
};

const VECTORS: Array<[number, TotpAlgorithm, string]> = [
  [59, 'SHA1', '94287082'],
  [59, 'SHA256', '46119246'],
  [59, 'SHA512', '90693936'],
  [1111111109, 'SHA1', '07081804'],
  [1111111109, 'SHA256', '68084774'],
  [1111111109, 'SHA512', '25091201'],
  [1111111111, 'SHA1', '14050471'],
  [1111111111, 'SHA256', '67062674'],
  [1111111111, 'SHA512', '99943326'],
  [1234567890, 'SHA1', '89005924'],
  [1234567890, 'SHA256', '91819424'],
  [1234567890, 'SHA512', '93441116'],
  [2000000000, 'SHA1', '69279037'],
  [2000000000, 'SHA256', '90698825'],
  [2000000000, 'SHA512', '38618901'],
  [20000000000, 'SHA1', '65353130'],
  [20000000000, 'SHA256', '77737706'],
  [20000000000, 'SHA512', '47863826'],
];

describe('generateTotp', () => {
  it.each(VECTORS)('matches RFC 6238 at t=%i with %s', (t, algorithm, expected) => {
    const { code } = generateTotp(SECRETS[algorithm], t, { algorithm, digits: 8, stepSeconds: 30 });
    expect(code).toBe(expected);
  });

  it('keeps leading zeros', () => {
    expect(generateTotp(SECRETS.SHA1, 1111111109, { algorithm: 'SHA1', digits: 8, stepSeconds: 30 }).code).toBe('07081804');
  });

  it('reports the seconds left in the step', () => {
    expect(generateTotp(SECRETS.SHA1, 59).remainingSeconds).toBe(1);
    expect(generateTotp(SECRETS.SHA1, 60).remainingSeconds).toBe(30);
  });
});

describe('verifyTotp', () => {
  const secret = SECRETS.SHA1;
  const now = 1_700_000_000;
  const codeAt = (t: number) => generateTotp(secret, t).code;

  it('accepts the current code', () => {
    expect(verifyTotp(secret, codeAt(now), now)).toEqual({ ok: true, counter: Math.floor(now / 30) });
  });

  it('accepts the previous and next step within the default window', () => {
    expect(verifyTotp(secret, codeAt(now - 30), now).ok).toBe(true);
    expect(verifyTotp(secret, codeAt(now + 30), now).ok).toBe(true);
  });

  it('rejects codes outside the window', () => {
    expect(verifyTotp(secret, codeAt(now - 60), now).ok).toBe(false);
    expect(verifyTotp(secret, codeAt(now - 30), now, { window: 0 }).ok).toBe(false);
  });

  it('rejects a code that was already used', () => {
    const first = verifyTotp(secret, codeAt(now), now);
    expect(verifyTotp(secret, codeAt(now), now + 5, { lastUsedCounter: first.counter! }).ok).toBe(false);
  });

  it('rejects input that is not a code of the right length', () => {
    expect(verifyTotp(secret, '12345', now).ok).toBe(false);
    expect(verifyTotp(secret, '12345a', now).ok).toBe(false);
    expect(verifyTotp(secret, '', now).ok).toBe(false);
  });
});
