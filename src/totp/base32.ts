import { randomBytes } from 'node:crypto';

// RFC 4648 base32, the encoding authenticator apps expect for TOTP secrets.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function decodeBase32(input: string): Uint8Array | null {
  const cleaned = input.replace(/\s+/g, '').toUpperCase().replace(/=+$/, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of cleaned) {
    const value = ALPHABET.indexOf(char);
    if (value === -1) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  // Leftover bits must be zero padding, otherwise the input was truncated.
  if (buffer !== 0) return null;
  return new Uint8Array(bytes);
}

export function encodeBase32(bytes: Uint8Array): string {
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += ALPHABET[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) output += ALPHABET[(buffer << (5 - bits)) & 0x1f];
  return output;
}

// 20 bytes = 160 bits, the length RFC 4226 recommends for HMAC-SHA1.
export function generateTotpSecret(): string {
  return encodeBase32(randomBytes(20));
}

export function buildOtpauthUri(input: { issuer: string; account: string; secret: string }): string {
  const label = encodeURIComponent(`${input.issuer}:${input.account}`);
  const params = new URLSearchParams({ secret: input.secret, issuer: input.issuer, algorithm: 'SHA1', digits: '6', period: '30' });
  return `otpauth://totp/${label}?${params.toString()}`;
}
