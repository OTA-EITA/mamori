import { createHmac, timingSafeEqual } from 'node:crypto';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpOptions {
  algorithm: TotpAlgorithm;
  digits: number;
  stepSeconds: number;
}

// RFC 6238 section 4 defaults, which is also what authenticator apps assume.
export const DEFAULT_TOTP_OPTIONS: TotpOptions = { algorithm: 'SHA1', digits: 6, stepSeconds: 30 };

const HMAC_NAMES: Record<TotpAlgorithm, string> = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };

// HOTP counters are 8 bytes (RFC 4226 section 5.2). At 30-second steps the
// counter stays below 2^31 until the year 4011, so the year 2038 limit is about
// the Unix time, not the counter: keep the time out of 32-bit math (no `t | 0`).
function counterBytes(counter: number): Uint8Array {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(counter), false);
  return new Uint8Array(view.buffer);
}

export function totpAt(secret: Uint8Array, counter: number, options: TotpOptions = DEFAULT_TOTP_OPTIONS): string {
  const hmac = createHmac(HMAC_NAMES[options.algorithm], secret).update(counterBytes(counter)).digest();
  // Dynamic truncation (RFC 4226 section 5.3). The offset comes from the last
  // byte, whose position depends on the hash length.
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary =
    ((hmac[offset]! & 0x7f) << 24) | (hmac[offset + 1]! << 16) | (hmac[offset + 2]! << 8) | hmac[offset + 3]!;
  // Keep leading zeros: codes are strings, not numbers.
  return String(binary % 10 ** options.digits).padStart(options.digits, '0');
}

export function generateTotp(
  secret: Uint8Array,
  unixSeconds: number,
  options: TotpOptions = DEFAULT_TOTP_OPTIONS,
): { code: string; remainingSeconds: number } {
  const counter = Math.floor(unixSeconds / options.stepSeconds);
  return {
    code: totpAt(secret, counter, options),
    remainingSeconds: options.stepSeconds - (unixSeconds % options.stepSeconds),
  };
}

export interface VerifyResult {
  ok: boolean;
  // The counter that matched. Store it and pass it back as `lastUsedCounter`
  // so the same code cannot be used twice.
  counter?: number;
}

export function verifyTotp(
  secret: Uint8Array,
  code: string,
  unixSeconds: number,
  opts: { window?: number; lastUsedCounter?: number; options?: TotpOptions } = {},
): VerifyResult {
  const options = opts.options ?? DEFAULT_TOTP_OPTIONS;
  const window = opts.window ?? 1;
  if (!/^\d+$/.test(code) || code.length !== options.digits) return { ok: false };

  const current = Math.floor(unixSeconds / options.stepSeconds);
  const given = Buffer.from(code);
  for (let delta = -window; delta <= window; delta++) {
    const counter = current + delta;
    if (counter < 0) continue;
    if (opts.lastUsedCounter !== undefined && counter <= opts.lastUsedCounter) continue;
    if (timingSafeEqual(Buffer.from(totpAt(secret, counter, options)), given)) return { ok: true, counter };
  }
  return { ok: false };
}
