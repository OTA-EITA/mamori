import { describe, expect, it } from 'vitest';
import { PASSKEY_SCRIPT } from './script.js';

describe('passkey.js', () => {
  it('is valid JavaScript', () => {
    expect(() => new Function(PASSKEY_SCRIPT)).not.toThrow();
  });

  it('uses no eval or inline handlers, so it runs under script-src self', () => {
    expect(PASSKEY_SCRIPT).not.toMatch(/\beval\(|new Function|innerHTML|onclick=/);
  });
});
