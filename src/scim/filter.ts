// The subset of SCIM filters (RFC 7644 §3.4.2.2) that provisioning clients
// actually send: `attr eq "value"`, joined with `and`. Anything else is an
// error, so a client never silently gets the wrong list.

export class ScimFilterError extends Error {}

export type EqFilter = Map<string, string>; // lower-cased attribute path -> value

export function parseFilter(input: string | null, allowed: string[]): EqFilter {
  const result: EqFilter = new Map();
  if (!input || !input.trim()) return result;
  const allowedLower = new Set(allowed.map((a) => a.toLowerCase()));
  // attr eq "value" (and ...)*  — values are JSON strings, so \" escapes work.
  // Operators are case-insensitive (RFC 7644 §3.4.2.2).
  const clause = /\s*([A-Za-z][\w.:]*)\s+eq\s+("(?:[^"\\]|\\.)*")\s*/iy;
  let pos = 0;
  for (;;) {
    clause.lastIndex = pos;
    const m = clause.exec(input);
    if (!m) throw new ScimFilterError(`Only "attribute eq \\"value\\"" filters joined with "and" are supported.`);
    const attr = m[1]!.toLowerCase().replace(/^urn:ietf:params:scim:schemas:core:2\.0:(user|group):/, '');
    if (!allowedLower.has(attr)) throw new ScimFilterError(`Filtering on ${m[1]} is not supported.`);
    result.set(attr, JSON.parse(m[2]!) as string);
    pos = clause.lastIndex;
    if (pos === input.length) return result;
    const and = /and\s+/iy;
    and.lastIndex = pos;
    if (!and.exec(input)) throw new ScimFilterError('Only "and" can join filter clauses.');
    pos = and.lastIndex;
  }
}
