import { randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuditLog } from '../audit/audit.js';
import { clientIp } from '../clientIp.js';
import { readJson } from '../http.js';
import type { User, UserStore } from '../store/users.js';
import type { Group, GroupStore } from '../store/groups.js';
import { parseFilter, ScimFilterError } from './filter.js';
import type { ScimTokens } from './tokens.js';

// SCIM 2.0 server (RFC 7643, RFC 7644), docs/v0.3.md "SCIM 2.0 server".

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
const MAX_PAGE = 200;

class ScimError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly scimType?: string,
  ) {
    super(message);
  }
}

function sendScim(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/scim+json', 'cache-control': 'no-store', ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

export interface ScimDeps {
  users: UserStore;
  groups?: GroupStore;
  tokens: ScimTokens;
  issuer: string;
  audit?: AuditLog;
  trustProxy?: boolean;
}

// SCIM clients send booleans as strings sometimes (Entra ID sends "False").
function toBool(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string' && /^(true|false)$/i.test(v)) return v.toLowerCase() === 'true';
  throw new ScimError(400, `Expected true or false, got ${JSON.stringify(v)}.`, 'invalidValue');
}

const isEmail = (v: unknown): v is string => typeof v === 'string' && /^[^\s@]+@[^\s@]+$/.test(v);

interface UserInput {
  userName?: unknown;
  displayName?: unknown;
  name?: { formatted?: unknown; givenName?: unknown; familyName?: unknown };
  emails?: { value?: unknown; primary?: unknown }[];
  active?: unknown;
  externalId?: unknown;
}

function nameOf(input: UserInput): string | undefined {
  const n = input.name;
  if (n && typeof n.formatted === 'string' && n.formatted.trim()) return n.formatted.trim();
  const parts = [n?.givenName, n?.familyName].filter((p): p is string => typeof p === 'string' && p.trim() !== '');
  if (parts.length) return parts.join(' ');
  if (typeof input.displayName === 'string' && input.displayName.trim()) return input.displayName.trim();
  return undefined;
}

function emailOf(input: UserInput): string | undefined {
  if (isEmail(input.userName)) return input.userName.toLowerCase();
  const primary = input.emails?.find((e) => e.primary === true || e.primary === 'true') ?? input.emails?.[0];
  return isEmail(primary?.value) ? primary.value.toLowerCase() : undefined;
}

export function scimHandler(deps: ScimDeps) {
  const base = new URL('/scim/v2/', deps.issuer).toString();
  const userJson = (u: User) => ({
    schemas: [USER_SCHEMA],
    id: u.id,
    ...(u.externalId ? { externalId: u.externalId } : {}),
    userName: u.email,
    name: { formatted: u.name },
    displayName: u.name,
    emails: [{ value: u.email, type: 'work', primary: true }],
    active: !u.disabled,
    meta: { resourceType: 'User', created: u.createdAt, lastModified: u.updatedAt ?? u.createdAt, location: `${base}Users/${u.id}` },
  });

  const visible = (id: string) => {
    const u = deps.users.findById(id);
    if (!u || u.deletedAt) throw new ScimError(404, `User ${id} not found.`);
    return u;
  };

  function setActive(u: User, active: boolean, log: (e: string, u: User) => void) {
    if (active === !u.disabled) return;
    deps.users.setDisabled(u.id, !active);
    log(active ? 'user.enabled' : 'user.disabled', u);
  }

  async function handleUsers(req: IncomingMessage, res: ServerResponse, url: URL, id: string | undefined, log: (e: string, u: User, extra?: Record<string, unknown>) => void) {
    if (req.method === 'GET' && !id) {
      const filter = parseFilter(url.searchParams.get('filter'), ['userName', 'externalId', 'emails.value']);
      const startIndex = Math.max(1, Number(url.searchParams.get('startIndex') ?? 1) || 1);
      const count = Math.min(MAX_PAGE, Math.max(0, Number(url.searchParams.get('count') ?? 100) || 0));
      const email = filter.get('username') ?? filter.get('emails.value');
      if (filter.has('username') && filter.has('emails.value') && filter.get('username')!.toLowerCase() !== filter.get('emails.value')!.toLowerCase()) {
        return sendScim(res, 200, { schemas: [LIST_SCHEMA], totalResults: 0, startIndex, itemsPerPage: 0, Resources: [] });
      }
      const { total, users } = deps.users.scimList({ ...(email !== undefined ? { email } : {}), ...(filter.has('externalid') ? { externalId: filter.get('externalid')! } : {}) }, startIndex - 1, count);
      return sendScim(res, 200, { schemas: [LIST_SCHEMA], totalResults: total, startIndex, itemsPerPage: users.length, Resources: users.map(userJson) });
    }
    if (req.method === 'GET' && id) return sendScim(res, 200, userJson(visible(id)));

    if (req.method === 'POST' && !id) {
      const input = (await readJson(req)) as UserInput;
      const email = emailOf(input);
      if (!email) throw new ScimError(400, 'userName must be an email address.', 'invalidValue');
      if (deps.users.findByEmail(email)) throw new ScimError(409, `A user with userName ${email} already exists.`, 'uniqueness');
      const name = nameOf(input) ?? email;
      // No usable password: the person signs in after an admin sends a setup link.
      const created = await deps.users.create({ email, name, password: randomBytes(32).toString('base64url') });
      if (typeof input.externalId === 'string') deps.users.updateProfile(created.id, { externalId: input.externalId });
      log('user.created', created);
      if (input.active !== undefined && !toBool(input.active)) setActive(deps.users.findById(created.id)!, false, log);
      const user = deps.users.findById(created.id)!;
      return sendScim(res, 201, userJson(user), { location: `${base}Users/${user.id}` });
    }

    if (!id) throw new ScimError(405, 'Method not allowed.');
    const user = visible(id);

    if (req.method === 'PUT') {
      const input = (await readJson(req)) as UserInput;
      const email = emailOf(input);
      if (!email) throw new ScimError(400, 'userName must be an email address.', 'invalidValue');
      const other = deps.users.findByEmail(email);
      if (other && other.id !== user.id) throw new ScimError(409, `A user with userName ${email} already exists.`, 'uniqueness');
      deps.users.updateProfile(user.id, { email, name: nameOf(input) ?? user.name, externalId: typeof input.externalId === 'string' ? input.externalId : null });
      log('user.updated', user);
      setActive(deps.users.findById(user.id)!, input.active === undefined ? true : toBool(input.active), log);
      return sendScim(res, 200, userJson(deps.users.findById(user.id)!));
    }

    if (req.method === 'PATCH') {
      const body = (await readJson(req)) as { schemas?: string[]; Operations?: { op?: string; path?: string; value?: unknown }[] };
      if (!Array.isArray(body.Operations)) throw new ScimError(400, `A PATCH body needs ${PATCH_SCHEMA} Operations.`, 'invalidSyntax');
      const changes: { email?: string; name?: string; externalId?: string | null } = {};
      let active: boolean | undefined;
      const apply = (path: string, value: unknown, op: string) => {
        const p = path.toLowerCase();
        if (op === 'remove') {
          if (p === 'externalid') return void (changes.externalId = null);
          throw new ScimError(400, `Cannot remove ${path}.`, 'mutability');
        }
        if (p === 'active') return void (active = toBool(value));
        if (p === 'username' || p === 'emails[type eq "work"].value' || p === 'emails.value') {
          if (!isEmail(value)) throw new ScimError(400, 'userName must be an email address.', 'invalidValue');
          return void (changes.email = value.toLowerCase());
        }
        if (p === 'displayname' || p === 'name.formatted') {
          if (typeof value !== 'string' || !value.trim()) throw new ScimError(400, `${path} must be text.`, 'invalidValue');
          return void (changes.name = value.trim());
        }
        if (p === 'name.givenname' || p === 'name.familyname') {
          if (typeof value !== 'string') throw new ScimError(400, `${path} must be text.`, 'invalidValue');
          const [given, family] = (changes.name ?? user.name).split(' ');
          changes.name = (p === 'name.givenname' ? [value, family] : [given, value]).filter(Boolean).join(' ');
          return;
        }
        if (p === 'externalid') return void (changes.externalId = typeof value === 'string' ? value : null);
        if (p === 'name' && value && typeof value === 'object') {
          const n = nameOf({ name: value as NonNullable<UserInput['name']> });
          if (n) changes.name = n;
          return;
        }
        if (p === 'emails' && Array.isArray(value)) {
          const e = emailOf({ emails: value as NonNullable<UserInput['emails']> });
          if (e) changes.email = e;
          return;
        }
        throw new ScimError(400, `Changing ${path} is not supported.`, 'invalidPath');
      };
      for (const op of body.Operations) {
        const kind = String(op.op ?? '').toLowerCase();
        if (!['add', 'replace', 'remove'].includes(kind)) throw new ScimError(400, `Unknown op ${op.op}.`, 'invalidSyntax');
        if (op.path) apply(op.path, op.value, kind);
        else if (op.value && typeof op.value === 'object') for (const [k, v] of Object.entries(op.value)) apply(k, v, kind);
        else throw new ScimError(400, 'An operation without a path needs an object value.', 'invalidSyntax');
      }
      if (changes.email && changes.email !== user.email) {
        const other = deps.users.findByEmail(changes.email);
        if (other && other.id !== user.id) throw new ScimError(409, `A user with userName ${changes.email} already exists.`, 'uniqueness');
      }
      if (Object.keys(changes).length) {
        deps.users.updateProfile(user.id, changes);
        log('user.updated', user, { fields: Object.keys(changes) });
      }
      if (active !== undefined) setActive(deps.users.findById(user.id)!, active, log);
      return sendScim(res, 200, userJson(deps.users.findById(user.id)!));
    }

    if (req.method === 'DELETE') {
      deps.users.markDeleted(user.id);
      log('user.deleted', user);
      return sendScim(res, 204);
    }
    throw new ScimError(405, 'Method not allowed.');
  }

  const groupJson = (g: Group) => ({
    schemas: [GROUP_SCHEMA],
    id: g.id,
    ...(g.externalId ? { externalId: g.externalId } : {}),
    displayName: g.name,
    members: deps.groups!.members(g.id).map((m) => ({ value: m.id, display: m.email, $ref: `${base}Users/${m.id}` })),
    meta: { resourceType: 'Group', location: `${base}Groups/${g.id}` },
  });

  // Member ids from a SCIM body; unknown or deleted users are an error, so a
  // typo does not silently drop someone from a group.
  const memberIds = (members: unknown): string[] => {
    if (members === undefined || members === null) return [];
    if (!Array.isArray(members)) throw new ScimError(400, 'members must be a list.', 'invalidValue');
    return members.map((m: { value?: unknown }) => {
      const id = typeof m?.value === 'string' ? m.value : '';
      const u = deps.users.findById(id);
      if (!u || u.deletedAt) throw new ScimError(400, `No user ${id || '(missing value)'}.`, 'invalidValue');
      return u.id;
    });
  };

  async function handleGroups(req: IncomingMessage, res: ServerResponse, url: URL, id: string | undefined, write: (event: string, extra: Record<string, unknown>) => void) {
    const groups = deps.groups;
    if (!groups) throw new ScimError(404, 'Groups are not available.');
    const nameOk = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v);
    if (req.method === 'GET' && !id) {
      const filter = parseFilter(url.searchParams.get('filter'), ['displayName', 'externalId']);
      let list = groups.list();
      if (filter.has('displayname')) list = list.filter((g) => g.name.toLowerCase() === filter.get('displayname')!.toLowerCase());
      if (filter.has('externalid')) list = list.filter((g) => g.externalId === filter.get('externalid'));
      const startIndex = Math.max(1, Number(url.searchParams.get('startIndex') ?? 1) || 1);
      const count = Math.min(MAX_PAGE, Math.max(0, Number(url.searchParams.get('count') ?? 100) || 0));
      const page = list.slice(startIndex - 1, startIndex - 1 + count);
      // Okta asks for excludedAttributes=members on large lists.
      const withMembers = !/\bmembers\b/.test(url.searchParams.get('excludedAttributes') ?? '');
      const json = (g: Group) => (withMembers ? groupJson(g) : { ...groupJson(g), members: undefined });
      return sendScim(res, 200, { schemas: [LIST_SCHEMA], totalResults: list.length, startIndex, itemsPerPage: page.length, Resources: page.map(json) });
    }
    const found = id ? groups.findById(id) : undefined;
    if (req.method === 'GET' && id) {
      if (!found) throw new ScimError(404, `Group ${id} not found.`);
      return sendScim(res, 200, groupJson(found));
    }
    if (req.method === 'POST' && !id) {
      const input = (await readJson(req)) as { displayName?: unknown; externalId?: unknown; members?: unknown };
      if (!nameOk(input.displayName)) throw new ScimError(400, 'displayName must be 1-64 letters, digits, dots, hyphens or underscores.', 'invalidValue');
      if (groups.findByName(input.displayName)) throw new ScimError(409, `A group named ${input.displayName} already exists.`, 'uniqueness');
      const ids = memberIds(input.members);
      const g = groups.create(input.displayName);
      if (typeof input.externalId === 'string') groups.setExternalId(g.id, input.externalId);
      groups.setMembers(g.id, ids);
      write('group.created', { group: g.name });
      const created = groups.findById(g.id)!;
      return sendScim(res, 201, groupJson(created), { location: `${base}Groups/${created.id}` });
    }
    if (!id || !found) throw new ScimError(404, `Group ${id} not found.`);
    if (req.method === 'PUT') {
      const input = (await readJson(req)) as { displayName?: unknown; externalId?: unknown; members?: unknown };
      if (!nameOk(input.displayName)) throw new ScimError(400, 'displayName must be 1-64 letters, digits, dots, hyphens or underscores.', 'invalidValue');
      const ids = memberIds(input.members);
      if (input.displayName !== found.name) groups.rename(found.id, input.displayName);
      groups.setExternalId(found.id, typeof input.externalId === 'string' ? input.externalId : null);
      groups.setMembers(found.id, ids);
      write('group.replaced', { group: input.displayName, members: ids.length });
      return sendScim(res, 200, groupJson(groups.findById(found.id)!));
    }
    if (req.method === 'PATCH') {
      const body = (await readJson(req)) as { Operations?: { op?: string; path?: string; value?: unknown }[] };
      if (!Array.isArray(body.Operations)) throw new ScimError(400, 'A PATCH body needs Operations.', 'invalidSyntax');
      for (const op of body.Operations) {
        const kind = String(op.op ?? '').toLowerCase();
        const path = (op.path ?? '').trim();
        // members[value eq "id"], the form Entra ID uses for removing one member.
        const one = /^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$/i.exec(path);
        if (kind === 'add' && /^members$/i.test(path)) {
          for (const uid of memberIds(op.value)) if (groups.addMember(found.id, uid)) write('group.member_added', { group: found.name, user_id: uid });
        } else if (kind === 'remove' && (one || /^members$/i.test(path))) {
          const ids = one ? [one[1]!] : op.value === undefined ? groups.members(found.id).map((m) => m.id) : memberIds(op.value);
          for (const uid of ids) if (groups.removeMember(found.id, uid)) write('group.member_removed', { group: found.name, user_id: uid });
        } else if (kind === 'replace' && /^members$/i.test(path)) {
          groups.setMembers(found.id, memberIds(op.value));
          write('group.replaced', { group: found.name });
        } else if (kind === 'replace' && (/^displayName$/i.test(path) || (!path && op.value && typeof op.value === 'object'))) {
          const v = path ? op.value : (op.value as { displayName?: unknown }).displayName;
          if (!nameOk(v)) throw new ScimError(400, 'displayName must be 1-64 letters, digits, dots, hyphens or underscores.', 'invalidValue');
          groups.rename(found.id, v);
          write('group.renamed', { group: v, from: found.name });
        } else if (/^externalId$/i.test(path)) {
          groups.setExternalId(found.id, kind === 'remove' || typeof op.value !== 'string' ? null : op.value);
        } else {
          throw new ScimError(400, `Unsupported operation ${op.op} ${path || '(no path)'}.`, 'invalidPath');
        }
      }
      return sendScim(res, 200, groupJson(groups.findById(found.id)!));
    }
    if (req.method === 'DELETE') {
      groups.delete(found.id);
      write('group.deleted', { group: found.name });
      return sendScim(res, 204);
    }
    throw new ScimError(405, 'Method not allowed.');
  }

  const discovery = (kind: string) => {
    if (kind === 'ServiceProviderConfig') {
      return {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
        patch: { supported: true },
        bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
        filter: { supported: true, maxResults: MAX_PAGE },
        changePassword: { supported: false },
        sort: { supported: false },
        etag: { supported: false },
        authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer token', description: 'A token made with mamori-admin scim token create.', primary: true }],
        meta: { resourceType: 'ServiceProviderConfig', location: `${base}ServiceProviderConfig` },
      };
    }
    const types = [
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/Users', schema: USER_SCHEMA, meta: { resourceType: 'ResourceType', location: `${base}ResourceTypes/User` } },
      ...(deps.groups ? [{ schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'Group', name: 'Group', endpoint: '/Groups', schema: GROUP_SCHEMA, meta: { resourceType: 'ResourceType', location: `${base}ResourceTypes/Group` } }] : []),
    ];
    if (kind === 'ResourceTypes') return { schemas: [LIST_SCHEMA], totalResults: types.length, startIndex: 1, itemsPerPage: types.length, Resources: types };
    const attr = (name: string, type: string, extra: Record<string, unknown> = {}) => ({ name, type, multiValued: false, required: false, mutability: 'readWrite', returned: 'default', uniqueness: 'none', ...extra });
    const schemas = [
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'], id: USER_SCHEMA, name: 'User', attributes: [attr('userName', 'string', { required: true, uniqueness: 'server' }), attr('name', 'complex'), attr('displayName', 'string'), attr('emails', 'complex', { multiValued: true }), attr('active', 'boolean'), attr('externalId', 'string')], meta: { resourceType: 'Schema', location: `${base}Schemas/${USER_SCHEMA}` } },
      { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'], id: GROUP_SCHEMA, name: 'Group', attributes: [attr('displayName', 'string', { required: true, uniqueness: 'server' }), attr('members', 'complex', { multiValued: true }), attr('externalId', 'string')], meta: { resourceType: 'Schema', location: `${base}Schemas/${GROUP_SCHEMA}` } },
    ];
    return { schemas: [LIST_SCHEMA], totalResults: schemas.length, startIndex: 1, itemsPerPage: schemas.length, Resources: schemas };
  };

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', deps.issuer);
    try {
      const auth = req.headers.authorization ?? '';
      const token = /^Bearer\s+(\S+)$/i.exec(auth)?.[1];
      const caller = token ? deps.tokens.verify(token) : undefined;
      if (!caller) {
        return sendScim(res, 401, { schemas: [ERROR_SCHEMA], status: '401', detail: 'A valid SCIM bearer token is required.' }, { 'www-authenticate': 'Bearer realm="mamori SCIM"' });
      }
      const ip = clientIp(req, deps.trustProxy ?? false);
      const log = (event: string, u: User, extra: Record<string, unknown> = {}) =>
        deps.audit?.write({ event, actor: { type: 'scim', id: caller.id, email: caller.name }, ip, user_id: u.id, user_email: u.email, ...extra });

      const m = /^\/scim\/v2\/(Users|Groups|ServiceProviderConfig|ResourceTypes|Schemas)(?:\/([^/]+))?$/.exec(url.pathname);
      if (!m) throw new ScimError(404, 'Not found.');
      if (m[1] === 'Users') return await handleUsers(req, res, url, m[2], log);
      if (m[1] === 'Groups') {
        const write = (event: string, extra: Record<string, unknown>) => deps.audit?.write({ event, actor: { type: 'scim', id: caller.id, email: caller.name }, ip, ...extra });
        return await handleGroups(req, res, url, m[2], write);
      }
      if (req.method !== 'GET') throw new ScimError(405, 'Method not allowed.');
      return sendScim(res, 200, discovery(m[1]!));
    } catch (err) {
      if (err instanceof ScimFilterError) return sendScim(res, 400, { schemas: [ERROR_SCHEMA], status: '400', scimType: 'invalidFilter', detail: err.message });
      if (err instanceof ScimError) return sendScim(res, err.status, { schemas: [ERROR_SCHEMA], status: String(err.status), ...(err.scimType ? { scimType: err.scimType } : {}), detail: err.message });
      if (err instanceof SyntaxError) return sendScim(res, 400, { schemas: [ERROR_SCHEMA], status: '400', scimType: 'invalidSyntax', detail: 'The body is not valid JSON.' });
      throw err;
    }
  };
}
