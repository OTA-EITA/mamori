import { describe, expect, it } from 'vitest';
import { resolveMfaPolicy } from './config.js';

describe('resolveMfaPolicy', () => {
  it('uses the config when it says', () => {
    expect(resolveMfaPolicy({ mfa: 'optional' }, 'v0.2').policy).toBe('optional');
    expect(resolveMfaPolicy({ mfa: 'required' }, 'v0.1')).toEqual({ policy: 'required' });
  });

  it('requires MFA for a new database and keeps v0.1 databases optional, with a warning', () => {
    expect(resolveMfaPolicy({}, 'v0.2')).toEqual({ policy: 'required' });
    const upgraded = resolveMfaPolicy({}, 'v0.1');
    expect(upgraded.policy).toBe('optional');
    expect(upgraded.warning).toMatch(/"mfa": "required"/);
  });

  it('refuses a value it does not know', () => {
    expect(() => resolveMfaPolicy({ mfa: 'always' as 'required' }, 'v0.2')).toThrow();
  });
});
