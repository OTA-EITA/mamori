import { describe, expect, it } from 'vitest';
import { parseFilter, ScimFilterError } from './filter.js';

const allowed = ['userName', 'externalId', 'emails.value'];

describe('parseFilter', () => {
  it('reads eq clauses joined with and, case-insensitively', () => {
    expect([...parseFilter('userName eq "a@example.com"', allowed)]).toEqual([['username', 'a@example.com']]);
    expect([...parseFilter('externalId EQ "42" AND userName eq "a@example.com"', allowed)]).toEqual([
      ['externalid', '42'],
      ['username', 'a@example.com'],
    ]);
    expect([...parseFilter('urn:ietf:params:scim:schemas:core:2.0:User:userName eq "x"', allowed)]).toEqual([['username', 'x']]);
    expect([...parseFilter('userName eq "has \\"quote\\" and and"', allowed)]).toEqual([['username', 'has "quote" and and']]);
    expect(parseFilter(null, allowed).size).toBe(0);
  });

  it('refuses what it does not support instead of guessing', () => {
    for (const f of ['userName co "a"', 'userName eq "a" or userName eq "b"', 'name.givenName eq "A"', 'userName eq a', 'userName eq "a" and']) {
      expect(() => parseFilter(f, allowed), f).toThrow(ScimFilterError);
    }
  });
});
