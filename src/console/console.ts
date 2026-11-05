import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import type { ClientMetadata } from 'oidc-provider';
import { renderSVG } from 'uqr';
import type { AuditLog } from '../audit/audit.js';
import { clientIp } from '../clientIp.js';
import { cookie, readCookie, readForm, readJson, redirect, send, sendJson, SCRIPT_CSP } from '../http.js';
import type { PasskeyStore } from '../store/passkeys.js';
import type { WebAuthn } from '../passkeys/webauthn.js';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { errorPage } from '../oidc/pages.js';
import type { UserStore } from '../store/users.js';
import { buildOtpauthUri, decodeBase32, generateTotpSecret } from '../totp/base32.js';
import { verifyTotp } from '../totp/totp.js';
import { accountPage, recoveryCodesPage, setupLinkInvalidPage, setupPage, signedOutPage, totpSetupPage } from './pages.js';
import type { SetupLinks } from './setupLinks.js';
import { adminAuditPage, adminProvisioningPage, adminDeniedPage, adminGroupPage, adminGroupsPage, adminNewUserPage, adminSetupLinkPage, adminUserPage, adminUsersPage, type UserRowView } from './adminPages.js';
import { randomBytes as randomPassword } from 'node:crypto';
import type { GroupStore } from '../store/groups.js';
import type { User } from '../store/users.js';
import type { RecoveryCodes } from './recovery.js';
import type { ConsoleSessions } from './sessions.js';

// The account page (and, later, the admin console). It is an OIDC client of
// mamori itself, `mamori-console`, so signing in goes through the same login,
// throttling and audit code as every other app.

export const CONSOLE_CLIENT_ID = 'mamori-console';
export const CALLBACK_PATH = '/console/callback';
export const SIGNED_OUT_PATH = '/account/signed-out';

const SESSION_COOKIE = 'mamori_console';
const STATE_COOKIE = 'mamori_console_state';
const LOGIN_TTL_SECONDS = 10 * 60;

export function consoleClient(issuer: string): ClientMetadata {
  return {
    client_id: CONSOLE_CLIENT_ID,
    client_name: 'Your account',
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: [new URL(CALLBACK_PATH, issuer).toString()],
    post_logout_redirect_uris: [new URL(SIGNED_OUT_PATH, issuer).toString()],
  };
}

export interface ConsoleDeps {
  provider: Provider;
  users: UserStore;
  sessions: ConsoleSessions;
  recovery: RecoveryCodes;
  issuer: string;
  totpIssuer: string;
  audit?: AuditLog;
  trustProxy?: boolean;
  now?: () => number;
  passkeys?: PasskeyStore;
  webauthn?: WebAuthn;
  groups?: GroupStore;
  setupLinks?: SetupLinks;
  provisioning?: { connectorNames: string[]; connectorGroups(): { name: string; group: string }[]; jobs(): ReturnType<import('../provisioning/engine.js').Provisioning['jobs']> };
}

const pkceChallenge = (verifier: string) => createHash('sha256').update(verifier).digest('base64url');

function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function consoleHandler(deps: ConsoleDeps) {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const secure = new URL(deps.issuer).protocol === 'https:';
  const redirectUri = new URL(CALLBACK_PATH, deps.issuer).toString();
  // Logins started from this browser that have not come back yet, by state.
  // In memory, like the sign-in throttling (one instance for now).
  const pendingLogins = new Map<string, { verifier: string; expires: number; returnTo: string }>();

  function startLogin(res: ServerResponse, returnTo = '/account'): void {
    for (const [k, v] of pendingLogins) if (v.expires <= now()) pendingLogins.delete(k);
    const state = randomBytes(24).toString('base64url');
    const verifier = randomBytes(32).toString('base64url');
    pendingLogins.set(state, { verifier, expires: now() + LOGIN_TTL_SECONDS, returnTo });
    const url = new URL('/auth', deps.issuer);
    url.search = new URLSearchParams({
      client_id: CONSOLE_CLIENT_ID,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: 'openid',
      state,
      code_challenge: pkceChallenge(verifier),
      code_challenge_method: 'S256',
    }).toString();
    redirect(res, url.pathname + url.search, { 'set-cookie': cookie(STATE_COOKIE, state, { secure, maxAge: LOGIN_TTL_SECONDS }) });
  }

  // The authorization code is checked and consumed here, inside the same
  // process, instead of calling the token endpoint over the network: mamori is
  // the provider, so it can read the code it issued. Everything the token
  // endpoint would check is checked: client, redirect URI, PKCE, one use.
  async function callback(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const state = url.searchParams.get('state') ?? '';
    const pending = pendingLogins.get(state);
    pendingLogins.delete(state);
    const fail = () => send(res, 400, errorPage('This sign-in did not work. Open your account page again.'));
    if (!pending || pending.expires <= now() || !sameString(readCookie(req, STATE_COOKIE) ?? '', state)) return fail();
    const code = await deps.provider.AuthorizationCode.find(url.searchParams.get('code') ?? '');
    if (
      !code ||
      !code.isValid ||
      code.clientId !== CONSOLE_CLIENT_ID ||
      code.redirectUri !== redirectUri ||
      code.codeChallengeMethod !== 'S256' ||
      !code.codeChallenge ||
      !sameString(code.codeChallenge, pkceChallenge(pending.verifier))
    ) {
      return fail();
    }
    await code.consume();
    const user = code.accountId ? deps.users.findById(code.accountId) : undefined;
    if (!user || user.disabled) return fail();
    const id = deps.sessions.create(user.id, code.amr ?? []);
    redirect(res, pending.returnTo, {
      'set-cookie': [cookie(SESSION_COOKIE, id, { secure }), cookie(STATE_COOKIE, '', { secure, maxAge: 0 })],
    });
  }

  const rowView = (u: User): UserRowView => ({
    id: u.id,
    email: u.email,
    name: u.name,
    disabled: u.disabled,
    isAdmin: u.isAdmin,
    hasTotp: u.totpSecret !== null,
    passkeys: deps.passkeys?.listByUser(u.id).length ?? 0,
    lastSignInAt: u.lastSignInAt,
  });

  // Admin pages (docs/v0.2.md, "Admin console"). They need an admin account
  // and a sign-in that used a second factor.
  async function admin(req: IncomingMessage, res: ServerResponse, url: URL, me: User, session: { amr: string[]; csrf: string }, ip: string): Promise<void> {
    const path = url.pathname;
    if (!me.isAdmin) return send(res, 403, adminDeniedPage('not_admin', session.csrf));
    if (!session.amr.includes('mfa')) return send(res, 403, adminDeniedPage('needs_mfa', session.csrf));
    const actor = { type: 'admin' as const, id: me.id, email: me.email };
    const log = (event: string, target: User, extra: Record<string, unknown> = {}) =>
      deps.audit?.write({ event, actor, client_id: CONSOLE_CLIENT_ID, ip, user_id: target.id, user_email: target.email, ...extra });
    const userPage = (status: number, target: User, extra: { notice?: string; error?: string } = {}) =>
      send(
        res,
        status,
        adminUserPage({
          user: rowView(target),
          self: target.id === me.id,
          groups: deps.groups?.namesOf(target.id) ?? [],
          passkeys: (deps.passkeys?.listByUser(target.id) ?? []).map((p) => ({ name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt })),
          events: deps.audit?.list({ actorId: target.id, limit: 20 }) ?? [],
          csrf: session.csrf,
          ...extra,
        }),
      );

    if (req.method === 'GET' && (path === '/admin' || path === '/admin/')) return redirect(res, '/admin/users');
    const linkFor = (target: User, created: boolean) => {
      const token = deps.setupLinks!.create(target.id);
      log('setup_link.created', target);
      return send(res, 200, adminSetupLinkPage({ email: target.email, userId: target.id, created, link: new URL(`/setup/${token}`, deps.issuer).toString() }));
    };
    if (path === '/admin/users/new' && deps.setupLinks) {
      if (req.method === 'GET') return send(res, 200, adminNewUserPage({ csrf: session.csrf }));
      const form = await readForm(req);
      if (!sameString(form.get('csrf') ?? '', session.csrf)) return send(res, 403, errorPage('This form has expired. Reload the page.'));
      const email = (form.get('email') ?? '').trim().toLowerCase();
      const name = (form.get('name') ?? '').trim();
      if (!/^[^\s@]+@[^\s@]+$/.test(email) || !name) return send(res, 400, adminNewUserPage({ csrf: session.csrf, email, name, error: 'Enter an email address and a name.' }));
      if (deps.users.findByEmail(email)) return send(res, 409, adminNewUserPage({ csrf: session.csrf, email, name, error: 'A user with this email already exists.' }));
      // A random password nobody knows, until the person chooses one with the link.
      const created = await deps.users.create({ email, name, password: randomPassword(32).toString('base64url') });
      log('user.created', created);
      return linkFor(created, true);
    }
    if (path === '/admin/provisioning' && req.method === 'GET') {
      return send(res, 200, adminProvisioningPage({ connectors: deps.provisioning?.connectorGroups() ?? [], jobs: deps.provisioning?.jobs() ?? [] }));
    }

    if (path === '/admin/audit' && req.method === 'GET') {
      const filter = { event: url.searchParams.get('event') ?? '', user: url.searchParams.get('user') ?? '', since: url.searchParams.get('since') ?? '', until: url.searchParams.get('until') ?? '' };
      const isDay = (d: string) => /^\d{4}-\d{2}-\d{2}$/.test(d);
      const nextDay = (d: string) => new Date(Date.parse(`${d}T00:00:00Z`) + 86_400_000).toISOString();
      const events =
        deps.audit?.list({
          ...(filter.event ? { event: filter.event } : {}),
          ...(filter.user ? { actorEmail: filter.user } : {}),
          ...(isDay(filter.since) ? { since: `${filter.since}T00:00:00.000Z` } : {}),
          ...(isDay(filter.until) ? { until: nextDay(filter.until) } : {}),
          limit: 200,
        }) ?? [];
      return send(res, 200, adminAuditPage({ events, filter }));
    }

    if ((path === '/admin/groups' || path.startsWith('/admin/groups/')) && deps.groups) {
      const groups = deps.groups;
      const listPage = (status: number, extra: { notice?: string; error?: string } = {}) =>
        send(res, status, adminGroupsPage({ groups: groups.list().map((g) => ({ ...g, members: groups.members(g.id).length })), csrf: session.csrf, ...extra }));
      if (path === '/admin/groups') {
        if (req.method === 'GET') return listPage(200);
        const form = await readForm(req);
        if (!sameString(form.get('csrf') ?? '', session.csrf)) return send(res, 403, errorPage('This form has expired. Reload the page.'));
        const name = (form.get('name') ?? '').trim();
        try {
          if (groups.findByName(name)) return listPage(409, { error: `A group named ${name} already exists.` });
          groups.create(name, (form.get('description') ?? '').trim());
        } catch (err) {
          return listPage(400, { error: err instanceof Error ? err.message : 'That group name cannot be used.' });
        }
        deps.audit?.write({ event: 'group.created', actor, client_id: CONSOLE_CLIENT_ID, ip, group: name });
        return listPage(200, { notice: `Added ${name}.` });
      }
      const gm = /^\/admin\/groups\/([^/]+)(?:\/(add|remove))?$/.exec(path);
      const group = gm ? groups.findByName(decodeURIComponent(gm[1]!)) : undefined;
      if (!gm || !group) return send(res, 404, errorPage('Not found.'));
      const groupPage = (status: number, extra: { notice?: string; error?: string } = {}) =>
        send(res, status, adminGroupPage({ ...group, members: groups.members(group.id), csrf: session.csrf, ...extra }));
      if (req.method === 'GET' && !gm[2]) return groupPage(200);
      if (req.method !== 'POST' || !gm[2]) return send(res, 404, errorPage('Not found.'));
      const form = await readForm(req);
      if (!sameString(form.get('csrf') ?? '', session.csrf)) return send(res, 403, errorPage('This form has expired. Reload the page.'));
      const member = deps.users.findByEmail((form.get('email') ?? '').trim().toLowerCase());
      if (!member) return groupPage(404, { error: 'No user with that email.' });
      if (gm[2] === 'add') {
        if (groups.addMember(group.id, member.id)) log('group.member_added', member, { group: group.name });
        return groupPage(200, { notice: `${member.email} is in ${group.name}.` });
      }
      if (groups.removeMember(group.id, member.id)) log('group.member_removed', member, { group: group.name });
      return groupPage(200, { notice: `${member.email} is no longer in ${group.name}.` });
    }

    if (req.method === 'GET' && path === '/admin/users') {
      const query = url.searchParams.get('q') ?? '';
      return send(res, 200, adminUsersPage({ users: deps.users.list(query).map(rowView), query, csrf: session.csrf }));
    }
    const m = /^\/admin\/users\/([\w-]+)(?:\/(disable|enable|reset-mfa|grant-admin|revoke-admin|setup-link))?$/.exec(path);
    const target = m ? deps.users.findById(m[1]!) : undefined;
    if (!m || !target) return send(res, 404, errorPage('Not found.'));
    if (req.method === 'GET' && !m[2]) return userPage(200, target);
    if (req.method !== 'POST' || !m[2]) return send(res, 404, errorPage('Not found.'));

    const form = await readForm(req);
    if (!sameString(form.get('csrf') ?? '', session.csrf)) return send(res, 403, errorPage('This form has expired. Reload the page.'));
    // Admins change their own account on the account page, so they cannot lock
    // themselves out from here.
    if (target.id === me.id) return userPage(400, target, { error: 'Use your account page to change your own account.' });

    switch (m[2]) {
      case 'disable':
        deps.users.setDisabled(target.id, true);
        log('user.disabled', target);
        return userPage(200, deps.users.findById(target.id)!, { notice: 'Disabled and signed out of every app.' });
      case 'enable':
        deps.users.setDisabled(target.id, false);
        log('user.enabled', target);
        return userPage(200, deps.users.findById(target.id)!, { notice: 'Enabled.' });
      case 'reset-mfa':
        deps.users.resetSecondFactors(target.id);
        log('user.mfa_reset', target);
        return userPage(200, deps.users.findById(target.id)!, { notice: 'Second factors removed. The user was signed out and sets them up again at the next sign-in.' });
      case 'setup-link':
        if (!deps.setupLinks) return send(res, 404, errorPage('Not found.'));
        // A new link is for a forgotten password, so sign the user out everywhere.
        deps.users.signOutEverywhere(target.id);
        return linkFor(target, false);
      case 'grant-admin':
        deps.users.setAdmin(target.id, true);
        log('admin.granted', target);
        return userPage(200, deps.users.findById(target.id)!, { notice: 'Now an administrator.' });
      default:
        deps.users.setAdmin(target.id, false);
        log('admin.revoked', target);
        return userPage(200, deps.users.findById(target.id)!, { notice: 'No longer an administrator.' });
    }
  }

  async function setupLink(req: IncomingMessage, res: ServerResponse, token: string): Promise<void> {
    const userId = deps.setupLinks!.check(token);
    const user = userId ? deps.users.findById(userId) : undefined;
    if (!user || user.disabled) return send(res, 410, setupLinkInvalidPage());
    if (req.method !== 'POST') return send(res, 200, setupPage({ email: user.email }));
    const form = await readForm(req);
    const password = form.get('password') ?? '';
    if (password.length < 12) return send(res, 400, setupPage({ email: user.email, error: 'Use 12 characters or more.' }));
    if (password !== form.get('confirm')) return send(res, 400, setupPage({ email: user.email, error: 'The two passwords are different.' }));
    if (!deps.setupLinks!.use(token)) return send(res, 410, setupLinkInvalidPage());
    await deps.users.setPassword(user.id, password);
    deps.audit?.write({ event: 'setup_link.used', actor: { type: 'user', id: user.id, email: user.email }, ip: clientIp(req, deps.trustProxy ?? false) });
    // Signing in next goes through the MFA setup step when the policy requires it.
    return redirect(res, '/account');
  }

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', deps.issuer);
    const path = url.pathname;
    if (req.method === 'GET' && path === CALLBACK_PATH) return callback(req, res, url);
    if (req.method === 'GET' && path === SIGNED_OUT_PATH) return send(res, 200, signedOutPage());
    const setup = /^\/setup\/([\w-]{20,})$/.exec(path);
    if (setup && deps.setupLinks) return setupLink(req, res, setup[1]!);

    const sessionId = readCookie(req, SESSION_COOKIE);
    const session = deps.sessions.get(sessionId);
    const user = session ? deps.users.findById(session.userId) : undefined;
    if (!session || !sessionId || !user || user.disabled) {
      // Come back to the page that was asked for, but only pages of the console.
      if (req.method === 'GET' && path === '/account') return startLogin(res);
      if (req.method === 'GET' && (path === '/admin' || /^\/admin\/[\w/-]*$/.test(path))) return startLogin(res, path);
      return redirect(res, '/account');
    }
    const ip = clientIp(req, deps.trustProxy ?? false);
    const actor = { type: 'user' as const, id: user.id, email: user.email };
    const log = (event: string, extra: Record<string, unknown> = {}) => deps.audit?.write({ event, actor, client_id: CONSOLE_CLIENT_ID, ip, ...extra });
    const view = (extra: { notice?: string; error?: string } = {}) => ({
      name: user.name,
      email: user.email,
      hasTotp: user.totpSecret !== null,
      recoveryCodesLeft: deps.recovery.remaining(user.id),
      csrf: session.csrf,
      ...(deps.webauthn ? { passkeys: (deps.passkeys?.listByUser(user.id) ?? []).map((p) => ({ id: p.id, name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt })) } : {}),
      ...extra,
    });
    const page = (status: number, html: string) => send(res, status, html, { 'content-security-policy': SCRIPT_CSP });

    if (path === '/admin' || path.startsWith('/admin/')) return admin(req, res, url, user, session, ip);

    if (req.method === 'GET' && path === '/account') return page(200, accountPage(view()));
    if (req.method !== 'POST') return send(res, 404, errorPage('Not found.'));

    // Passkey registration is driven by /assets/passkey.js with JSON, so the
    // CSRF token comes in a header instead of a form field.
    if ((path === '/account/passkeys/options' || path === '/account/passkeys/register') && deps.webauthn && deps.passkeys) {
      if (!sameString(String(req.headers['x-csrf-token'] ?? ''), session.csrf)) return sendJson(res, 403, { error: 'This page has expired. Reload it.' });
      if (path === '/account/passkeys/options') {
        const options = await deps.webauthn.registrationOptions(user, deps.passkeys.listByUser(user.id));
        deps.sessions.setPendingChallenge(sessionId, options.challenge);
        return sendJson(res, 200, options);
      }
      const body = (await readJson(req)) as { response?: RegistrationResponseJSON; name?: string };
      const challenge = session.pendingChallenge;
      deps.sessions.setPendingChallenge(sessionId, null);
      let created: Awaited<ReturnType<WebAuthn['verifyRegistration']>>;
      try {
        created = challenge && body.response ? await deps.webauthn.verifyRegistration(body.response, challenge) : undefined;
      } catch {
        created = undefined;
      }
      if (!created) return sendJson(res, 400, { error: 'The passkey could not be added. Try again.' });
      const name = (body.name ?? '').trim().slice(0, 60) || `Passkey added ${new Date(now() * 1000).toISOString().slice(0, 10)}`;
      deps.passkeys.add({ ...created, userId: user.id, name });
      log('passkey.added', { passkey: name, synced: created.backedUp });
      return sendJson(res, 200, { location: '/account' });
    }

    const form = await readForm(req);
    if (!sameString(form.get('csrf') ?? '', session.csrf)) return send(res, 403, errorPage('This form has expired. Open your account page again.'));

    if (path === '/account/logout') {
      deps.sessions.delete(sessionId);
      log('sign_out');
      // End the mamori session too, so the next visit asks for credentials.
      const end = new URL('/session/end', deps.issuer);
      end.search = new URLSearchParams({ client_id: CONSOLE_CLIENT_ID, post_logout_redirect_uri: new URL(SIGNED_OUT_PATH, deps.issuer).toString() }).toString();
      return redirect(res, end.pathname + end.search, { 'set-cookie': cookie(SESSION_COOKIE, '', { secure, maxAge: 0 }) });
    }

    if (path === '/account/totp/start') {
      if (user.totpSecret) return page(409, accountPage(view({ error: 'An authenticator app is already set up. Remove it first.' })));
      const secret = generateTotpSecret();
      deps.sessions.setPendingTotp(sessionId, secret);
      const uri = buildOtpauthUri({ issuer: deps.totpIssuer, account: user.email, secret });
      return send(res, 200, totpSetupPage({ qrSvg: renderSVG(uri), secret, csrf: session.csrf }));
    }

    if (path === '/account/totp/confirm') {
      const secret = session.pendingTotp;
      if (!secret) return redirect(res, '/account');
      const result = verifyTotp(decodeBase32(secret)!, (form.get('code') ?? '').trim(), now());
      if (!result.ok || result.counter === undefined) {
        const uri = buildOtpauthUri({ issuer: deps.totpIssuer, account: user.email, secret });
        return send(res, 400, totpSetupPage({ qrSvg: renderSVG(uri), secret, csrf: session.csrf, error: 'That code is not correct. Check the time on your phone and try again.' }));
      }
      deps.users.setTotpSecret(user.id, secret);
      deps.users.setTotpLastCounter(user.id, result.counter);
      deps.sessions.setPendingTotp(sessionId, null);
      log('totp.added');
      // People who turn on two-step verification also need a way back in.
      if (deps.recovery.remaining(user.id) === 0) {
        const codes = deps.recovery.generate(user.id);
        log('recovery_codes.generated');
        return send(res, 200, recoveryCodesPage({ codes, intro: 'Your authenticator app is set up.' }));
      }
      return page(200, accountPage(view({ notice: 'Your authenticator app is set up.' })));
    }

    if (path === '/account/totp/remove') {
      // A current code is required, so a stolen session alone cannot turn off
      // two-step verification.
      const secret = user.totpSecret ? decodeBase32(user.totpSecret) : null;
      const result = secret
        ? verifyTotp(secret, (form.get('code') ?? '').trim(), now(), user.totpLastCounter !== null ? { lastUsedCounter: user.totpLastCounter } : {})
        : { ok: false };
      if (!result.ok) return page(400, accountPage(view({ error: 'That code is not correct.' })));
      deps.users.setTotpSecret(user.id, null);
      log('totp.removed');
      return page(200, accountPage({ ...view({ notice: 'The authenticator app was removed.' }), hasTotp: false }));
    }

    if (path === '/account/passkeys/remove' && deps.passkeys) {
      const id = form.get('id') ?? '';
      const passkey = deps.passkeys.find(id);
      if (!passkey || !deps.passkeys.remove(user.id, id)) return page(404, accountPage(view({ error: 'That passkey was not found.' })));
      log('passkey.removed', { passkey: passkey.name });
      return page(200, accountPage(view({ notice: `Removed ${passkey.name}.` })));
    }

    if (path === '/account/recovery-codes') {
      const codes = deps.recovery.generate(user.id);
      log('recovery_codes.generated');
      return send(res, 200, recoveryCodesPage({ codes, intro: 'New recovery codes. The old ones no longer work.' }));
    }

    return send(res, 404, errorPage('Not found.'));
  };
}
