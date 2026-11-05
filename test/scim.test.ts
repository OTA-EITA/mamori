import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditLog, type AuditRecord } from '../src/audit/audit.js';
import { scimHandler } from '../src/scim/scim.js';
import { ScimTokens } from '../src/scim/tokens.js';
import { openDatabase } from '../src/store/db.js';
import { SecretBox } from '../src/store/secretBox.js';
import { UserStore } from '../src/store/users.js';
import { GroupStore } from '../src/store/groups.js';

let server: Server;
let base: string;
let token: string;
let users: UserStore;
let groups: GroupStore;
const lines: string[] = [];
const events = () => lines.map((l) => JSON.parse(l) as AuditRecord);

beforeAll(async () => {
  const db = openDatabase(':memory:');
  users = new UserStore(db, new SecretBox(randomBytes(32)));
  groups = new GroupStore(db);
  const tokens = new ScimTokens(db);
  token = tokens.create('Entra ID').token;
  const audit = new AuditLog(db, { sink: (l) => lines.push(l) });
  let handle: ReturnType<typeof scimHandler>;
  server = createServer((req, res) => void handle(req, res));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  handle = scimHandler({ users, groups, tokens, audit, issuer });
  base = `${issuer}/scim/v2`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

async function scim(method: string, path: string, body?: unknown, auth = token) {
  const res = await fetch(base + path, {
    method,
    headers: { authorization: `Bearer ${auth}`, 'content-type': 'application/scim+json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined, type: res.headers.get('content-type') };
}

const newUser = (email: string, extra: Record<string, unknown> = {}) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  userName: email,
  name: { givenName: 'Taro', familyName: 'Yamada' },
  emails: [{ value: email, type: 'work', primary: true }],
  active: true,
  ...extra,
});

describe('SCIM Users', () => {
  it('needs a valid bearer token', async () => {
    expect((await scim('GET', '/Users', undefined, 'mamori_scim_wrong')).status).toBe(401);
    expect((await scim('GET', '/Users', undefined, '')).status).toBe(401);
  });

  it('creates a user, refuses a duplicate, and finds it by filter', async () => {
    const created = await scim('POST', '/Users', newUser('taro@example.co.jp', { externalId: 'hr-001' }));
    expect(created.status).toBe(201);
    expect(created.type).toBe('application/scim+json');
    expect(created.body).toMatchObject({ userName: 'taro@example.co.jp', name: { formatted: 'Taro Yamada' }, active: true, externalId: 'hr-001' });
    expect(users.findByEmail('taro@example.co.jp')!.name).toBe('Taro Yamada');

    const dup = await scim('POST', '/Users', newUser('TARO@example.co.jp'));
    expect(dup.status).toBe(409);
    expect(dup.body.scimType).toBe('uniqueness');

    const found = await scim('GET', `/Users?filter=${encodeURIComponent('userName eq "Taro@Example.co.jp"')}`);
    expect(found.body).toMatchObject({ totalResults: 1, Resources: [{ id: created.body.id }] });
    const byExternal = await scim('GET', `/Users?filter=${encodeURIComponent('externalId eq "hr-001"')}`);
    expect(byExternal.body.totalResults).toBe(1);
    const none = await scim('GET', `/Users?filter=${encodeURIComponent('userName eq "nobody@example.co.jp"')}`);
    expect(none.body).toMatchObject({ totalResults: 0, Resources: [] });
    const unsupported = await scim('GET', `/Users?filter=${encodeURIComponent('userName co "taro"')}`);
    expect(unsupported.status).toBe(400);
    expect(unsupported.body.scimType).toBe('invalidFilter');
  });

  it('pages through users', async () => {
    for (const n of [1, 2, 3]) await scim('POST', '/Users', newUser(`page${n}@example.co.jp`));
    const first = await scim('GET', '/Users?startIndex=1&count=2');
    const second = await scim('GET', '/Users?startIndex=3&count=2');
    expect(first.body.itemsPerPage).toBe(2);
    expect(first.body.totalResults).toBe(second.body.totalResults);
    const ids = [...first.body.Resources, ...second.body.Resources].map((u: { id: string }) => u.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('accepts the PATCH forms Entra ID and Okta send', async () => {
    const { body: u } = await scim('POST', '/Users', newUser('hanako@example.co.jp'));
    // Entra ID: capitalised op, no path, boolean as a string.
    const entra = await scim('PATCH', `/Users/${u.id}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Replace', value: { active: 'False' } }],
    });
    expect(entra.status).toBe(200);
    expect(entra.body.active).toBe(false);
    expect(users.findById(u.id)!.disabled).toBe(true);
    // Okta: lower-case op with a path.
    const okta = await scim('PATCH', `/Users/${u.id}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [
        { op: 'replace', path: 'active', value: true },
        { op: 'replace', path: 'name.familyName', value: 'Suzuki' },
        { op: 'replace', path: 'emails[type eq "work"].value', value: 'hanako.suzuki@example.co.jp' },
      ],
    });
    expect(okta.body).toMatchObject({ active: true, userName: 'hanako.suzuki@example.co.jp', name: { formatted: 'Taro Suzuki' } });
    // The id stays, so apps keep the same `sub`.
    expect(okta.body.id).toBe(u.id);
    const bad = await scim('PATCH', `/Users/${u.id}`, { Operations: [{ op: 'replace', path: 'password', value: 'x' }] });
    expect(bad.status).toBe(400);
  });

  it('replaces a user with PUT', async () => {
    const { body: u } = await scim('POST', '/Users', newUser('jiro@example.co.jp'));
    const put = await scim('PUT', `/Users/${u.id}`, newUser('jiro@example.co.jp', { name: { formatted: 'Jiro Tanaka' }, active: false }));
    expect(put.body).toMatchObject({ name: { formatted: 'Jiro Tanaka' }, active: false });
  });

  it('disables and hides a deleted user, keeping the audit trail', async () => {
    const { body: u } = await scim('POST', '/Users', newUser('leaver@example.co.jp'));
    expect((await scim('DELETE', `/Users/${u.id}`)).status).toBe(204);
    expect((await scim('GET', `/Users/${u.id}`)).status).toBe(404);
    expect((await scim('GET', `/Users?filter=${encodeURIComponent('userName eq "leaver@example.co.jp"')}`)).body.totalResults).toBe(0);
    const stored = users.findById(u.id)!;
    expect(stored.disabled).toBe(true);
    expect(stored.deletedAt).not.toBeNull();
    const deleted = events().find((e) => e.event === 'user.deleted');
    expect(deleted).toMatchObject({ actor: { type: 'scim', email: 'Entra ID' }, user_email: 'leaver@example.co.jp' });
    expect(lines.join('\n')).not.toContain(token);
  });
});

describe('SCIM Groups', () => {
  it('creates a group with members and finds it by name', async () => {
    const { body: a } = await scim('POST', '/Users', newUser('g-a@example.co.jp'));
    const { body: b } = await scim('POST', '/Users', newUser('g-b@example.co.jp'));
    const unknown = await scim('POST', '/Groups', { displayName: 'nope', members: [{ value: 'no-such-user' }] });
    expect(unknown.status).toBe(400);
    const created = await scim('POST', '/Groups', { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: 'engineering', externalId: 'g-1', members: [{ value: a.id }, { value: b.id }] });
    expect(created.status).toBe(201);
    expect(created.body.members.map((m: { value: string }) => m.value).sort()).toEqual([a.id, b.id].sort());
    expect(groups.namesOf(a.id)).toEqual(['engineering']);
    expect((await scim('POST', '/Groups', { displayName: 'Engineering' })).status).toBe(409);
    const found = await scim('GET', `/Groups?filter=${encodeURIComponent('displayName eq "engineering"')}&excludedAttributes=members`);
    expect(found.body.totalResults).toBe(1);
    expect(found.body.Resources[0].members).toBeUndefined();
  });

  it('adds and removes members the way Entra ID and Okta do, renames and deletes', async () => {
    const { body: c } = await scim('POST', '/Users', newUser('g-c@example.co.jp'));
    const { body: d } = await scim('POST', '/Users', newUser('g-d@example.co.jp'));
    const { body: g } = await scim('POST', '/Groups', { displayName: 'sales', members: [{ value: c.id }] });
    await scim('PATCH', `/Groups/${g.id}`, { Operations: [{ op: 'Add', path: 'members', value: [{ value: d.id }] }] });
    expect(groups.members(g.id).length).toBe(2);
    // Entra ID removes one member with a filter in the path.
    await scim('PATCH', `/Groups/${g.id}`, { Operations: [{ op: 'Remove', path: `members[value eq "${c.id}"]` }] });
    expect(groups.members(g.id).map((m) => m.id)).toEqual([d.id]);
    // Okta removes with a value list.
    await scim('PATCH', `/Groups/${g.id}`, { Operations: [{ op: 'remove', path: 'members', value: [{ value: d.id }] }] });
    expect(groups.members(g.id)).toEqual([]);
    const renamed = await scim('PATCH', `/Groups/${g.id}`, { Operations: [{ op: 'replace', value: { displayName: 'sales-jp' } }] });
    expect(renamed.body.displayName).toBe('sales-jp');
    expect((await scim('DELETE', `/Groups/${g.id}`)).status).toBe(204);
    expect((await scim('GET', `/Groups/${g.id}`)).status).toBe(404);
    expect(events().filter((e) => e.event.startsWith('group.')).map((e) => e.event)).toEqual(
      expect.arrayContaining(['group.member_added', 'group.member_removed', 'group.renamed', 'group.deleted']),
    );
  });
});

describe('SCIM discovery', () => {
  it('describes what is supported', async () => {
    const config = await scim('GET', '/ServiceProviderConfig');
    expect(config.body).toMatchObject({ patch: { supported: true }, bulk: { supported: false }, filter: { supported: true }, changePassword: { supported: false } });
    const types = await scim('GET', '/ResourceTypes');
    expect(types.body.Resources.map((t: { id: string }) => t.id)).toEqual(['User', 'Group']);
    const schemas = await scim('GET', '/Schemas');
    expect(schemas.body.totalResults).toBe(2);
    expect((await scim('POST', '/ServiceProviderConfig', {})).status).toBe(405);
  });
});
