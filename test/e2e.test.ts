import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as client from 'openid-client';
import { createProvider } from '../src/oidc/provider.js';
import { createServer } from 'node:http';
import { createRequestHandler } from '../src/server.js';
import { openDatabase } from '../src/store/db.js';
import { UserStore } from '../src/store/users.js';
import { decodeBase32, generateTotpSecret } from '../src/totp/base32.js';
import { generateTotp } from '../src/totp/totp.js';
import { AuditLog, type AuditRecord } from '../src/audit/audit.js';
import { GroupStore } from '../src/store/groups.js';
import { consoleHandler } from '../src/console/console.js';
import { RecoveryCodes } from '../src/console/recovery.js';
import { ConsoleSessions } from '../src/console/sessions.js';
import { PasskeyStore } from '../src/store/passkeys.js';
import { WebAuthn } from '../src/passkeys/webauthn.js';
import { SoftAuthenticator } from './authenticator.js';
import { SecretBox } from '../src/store/secretBox.js';
import { randomBytes } from 'node:crypto';

const testBox = new SecretBox(randomBytes(32));

const REDIRECT_URI = 'http://127.0.0.1:9/callback';

let server: Server;
let issuer: string;
let users: UserStore;
const totpSecret = generateTotpSecret();
const ginaSecret = generateTotpSecret();

// A tiny browser: keeps cookies and follows redirects until it reaches a page
// or the client's redirect_uri.
class Browser {
  private readonly cookies = new Map<string, string>();

  async go(url: string, init: { method?: string; form?: Record<string, string>; json?: unknown; headers?: Record<string, string> } = {}): Promise<{ url: string; status: number; body: string }> {
    let current = url;
    let method = init.method ?? 'GET';
    let body: string | undefined = init.json !== undefined ? JSON.stringify(init.json) : init.form ? new URLSearchParams(init.form).toString() : undefined;
    let extra = init.headers ?? {};
    for (let hops = 0; hops < 20; hops++) {
      if (current.startsWith(REDIRECT_URI)) return { url: current, status: 0, body: '' };
      const headers: Record<string, string> = { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '), ...extra };
      if (body) headers['content-type'] = init.json !== undefined ? 'application/json' : 'application/x-www-form-urlencoded';
      const res = await fetch(current, { method, headers, redirect: 'manual', ...(body ? { body } : {}) });
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(';');
        const [k, ...v] = pair!.split('=');
        this.cookies.set(k!, v.join('='));
      }
      const location = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && location) {
        current = new URL(location, current).toString();
        method = 'GET';
        body = undefined;
        extra = {};
        continue;
      }
      return { url: current, status: res.status, body: await res.text() };
    }
    throw new Error('too many redirects');
  }
}

function formAction(html: string): string {
  const m = /<form method="post" action="([^"]+)"/.exec(html);
  if (!m) throw new Error(`no form in page: ${html.slice(0, 200)}`);
  return new URL(m[1]!, issuer).toString();
}

async function startLogin(browser: Browser, config: client.Configuration, scope = 'openid email profile') {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
  });
  return { page: await browser.go(url.toString()), verifier, state };
}

const sleeps: number[] = [];
let mfaPolicy: 'optional' | 'required' = 'optional';
const auditLines: string[] = [];
const events = (): AuditRecord[] => auditLines.map((l) => JSON.parse(l) as AuditRecord);

beforeAll(async () => {
  const db = openDatabase(':memory:');
  users = new UserStore(db, testBox);
  const audit = new AuditLog(db, { sink: (line) => auditLines.push(line) });
  const groups = new GroupStore(db);
  let handler: ReturnType<typeof createRequestHandler> | undefined;
  server = createServer((req, res) => handler!(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const provider = createProvider(
    {
      issuer,
      port: 0,
      database: ':memory:',
      totpIssuer: 'mamori-test',
      encryptionKeyFile: '',
      auditLog: 'off',
      auditRetentionDays: 400,
      clients: [{ client_id: 'app', client_secret: 'app-secret', redirect_uris: [REDIRECT_URI], client_name: 'Test App' }],
    },
    db,
    users,
    audit,
    groups,
  );
  // No real waiting for the throttling delays in tests; record them instead.
  const recovery = new RecoveryCodes(db);
  const now = () => Math.floor(Date.now() / 1000);
  const passkeys = new PasskeyStore(db);
  const webauthn = new WebAuthn(issuer, 'mamori-test');
  const account = consoleHandler({ provider, users, sessions: new ConsoleSessions(db, testBox, now), recovery, audit, passkeys, webauthn, issuer, totpIssuer: 'mamori-test' });
  handler = createRequestHandler(provider, users, { audit, recovery, console: account, mfaPolicy: () => mfaPolicy, totpIssuer: 'mamori-test', passkeys, webauthn, sleep: async (seconds) => void sleeps.push(seconds) });
  const alice = await users.create({ email: 'alice@example.com', name: 'Alice', password: 'alice-password-1' });
  for (const name of ['engineering', 'all-staff']) groups.addMember(groups.create(name).id, alice.id);
  const carol = await users.create({ email: 'carol@example.com', name: 'Carol', password: 'carol-password' });
  users.setDisabled(carol.id, true);
  await users.create({ email: 'dave@example.com', name: 'Dave', password: 'dave-password-1' });
  const bob = await users.create({ email: 'bob@example.com', name: 'Bob', password: 'bob-password-12' });
  users.setTotpSecret(bob.id, totpSecret);
  await users.create({ email: 'frank@example.com', name: 'Frank', password: 'frank-password-1' });
  await users.create({ email: 'hana@example.com', name: 'Hana', password: 'hana-password-1' });
  await users.create({ email: 'ivy@example.com', name: 'Ivy', password: 'ivy-password-12' });
  const gina = await users.create({ email: 'gina@example.com', name: 'Gina', password: 'gina-password-1' });
  users.setTotpSecret(gina.id, ginaSecret);
  const erin = await users.create({ email: 'erin@example.com', name: 'Erin', password: 'erin-password-1' });
  users.setTotpSecret(erin.id, generateTotpSecret());
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

async function discover(): Promise<client.Configuration> {
  return client.discovery(new URL(issuer), 'app', 'app-secret', undefined, { execute: [client.allowInsecureRequests] });
}

describe('sign-in with authorization code + PKCE', () => {
  it('signs in with a password and returns ID token claims and userinfo', async () => {
    const config = await discover();
    const browser = new Browser();
    const { page, verifier, state } = await startLogin(browser, config);
    expect(page.body).toContain('Sign in');
    expect(page.body).toContain('Test App');

    const done = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'alice@example.com', password: 'alice-password-1' } });
    expect(done.url.startsWith(REDIRECT_URI)).toBe(true);

    const tokens = await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
    const claims = tokens.claims()!;
    expect(claims.email).toBe('alice@example.com');
    expect(claims.amr).toEqual(['pwd']);
    const info = await client.fetchUserInfo(config, tokens.access_token, claims.sub);
    expect(info.name).toBe('Alice');
  });

  it('asks for a TOTP code when the user has one', async () => {
    const config = await discover();
    const browser = new Browser();
    const { page, verifier, state } = await startLogin(browser, config);
    const totp = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'bob@example.com', password: 'bob-password-12' } });
    expect(totp.body).toContain('Verify it is you');

    const wrong = await browser.go(formAction(totp.body), { method: 'POST', form: { code: '000000' } });
    expect(wrong.status).toBe(401);

    const code = generateTotp(decodeBase32(totpSecret)!, Math.floor(Date.now() / 1000)).code;
    const done = await browser.go(formAction(wrong.body), { method: 'POST', form: { code } });
    expect(done.url.startsWith(REDIRECT_URI)).toBe(true);
    const tokens = await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
    expect(tokens.claims()!.amr).toEqual(['pwd', 'otp', 'mfa']);
  });

  it('rejects a wrong password without saying which part was wrong', async () => {
    const config = await discover();
    const browser = new Browser();
    const { page } = await startLogin(browser, config);
    const res = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'alice@example.com', password: 'nope' } });
    expect(res.status).toBe(401);
    expect(res.body).toContain('The email or password is not correct.');
  });

  it('refuses a disabled user even with the right password', async () => {
    const config = await discover();
    const browser = new Browser();
    const { page } = await startLogin(browser, config);
    const res = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'carol@example.com', password: 'carol-password' } });
    expect(res.status).toBe(401);
  });

  it('locks the account for a while after 10 failed attempts', async () => {
    const config = await discover();
    const browser = new Browser();
    let { page } = await startLogin(browser, config);
    for (let i = 0; i < 10; i++) {
      page = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'dave@example.com', password: `wrong-${i}` } });
      expect(page.status).toBe(401);
    }
    const locked = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'dave@example.com', password: 'dave-password-1' } });
    expect(locked.status).toBe(429);
  });

  it('slows down and then stops TOTP guesses the same way as password guesses', async () => {
    const config = await discover();
    const browser = new Browser();
    const { page } = await startLogin(browser, config);
    let res = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'erin@example.com', password: 'erin-password-1' } });
    expect(res.body).toContain('Verify it is you');
    sleeps.length = 0;
    for (let i = 0; i < 10; i++) {
      res = await browser.go(formAction(res.body), { method: 'POST', form: { code: 'wrong!' } });
      expect(res.status).toBe(401);
    }
    // Each failure after the fifth doubles the delay before the next answer.
    expect(sleeps).toEqual([0, 0, 0, 0, 0, 0, 1, 2, 4, 8]);
    // The tenth failure locks this IP out for this email, including the password step.
    const again = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'erin@example.com', password: 'erin-password-1' } });
    expect(again.status).toBe(429);
  });

  it('writes the sign-in and token events to the audit log, without secrets', async () => {
    auditLines.length = 0;
    const config = await discover();
    const browser = new Browser();
    const { page, verifier, state } = await startLogin(browser, config);
    const wrong = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'bob@example.com', password: 'not-the-password' } });
    const totp = await browser.go(formAction(wrong.body), { method: 'POST', form: { email: 'bob@example.com', password: 'bob-password-12' } });
    const bad = await browser.go(formAction(totp.body), { method: 'POST', form: { code: '000001' } });
    // Wait for the next time step so the code is not one already used by another test.
    const code = generateTotp(decodeBase32(totpSecret)!, Math.floor(Date.now() / 1000) + 30).code;
    const done = await browser.go(formAction(bad.body), { method: 'POST', form: { code } });
    await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });

    const names = events().map((e) => e.event);
    expect(names).toEqual(['sign_in.failed', 'mfa.challenge_failed', 'sign_in.succeeded', 'token.issued']);
    const [failed, challenge, succeeded, token] = events();
    expect(failed).toMatchObject({ actor: { type: 'user', email: 'bob@example.com' }, client_id: 'app', ip: '127.0.0.1', reason: 'wrong_password' });
    expect(challenge).toMatchObject({ method: 'otp' });
    expect(succeeded).toMatchObject({ amr: ['pwd', 'otp', 'mfa'], actor: { email: 'bob@example.com' } });
    expect(token).toMatchObject({ token_type: 'access_token', client_id: 'app', scope: 'openid email profile' });
    expect(auditLines.join('\n')).not.toMatch(/not-the-password|bob-password-12|000001/);
    expect(auditLines.join('\n')).not.toContain(code);
    expect(users.findByEmail('bob@example.com')!.lastSignInAt).not.toBeNull();
  });

  it('puts the user’s groups in the ID token and userinfo when the app asks for them', async () => {
    const config = await discover();
    for (const [scope, expected] of [
      ['openid email profile groups', ['all-staff', 'engineering']],
      ['openid email profile', undefined],
    ] as const) {
      const browser = new Browser();
      const { page, verifier, state } = await startLogin(browser, config, scope);
      const done = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'alice@example.com', password: 'alice-password-1' } });
      const tokens = await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
      const claims = tokens.claims()!;
      expect(claims.groups).toEqual(expected);
      const info = await client.fetchUserInfo(config, tokens.access_token, claims.sub);
      expect(info.groups).toEqual(expected);
    }
  });

  it('refuses an authorization request without PKCE', async () => {
    const config = await discover();
    const url = client.buildAuthorizationUrl(config, { redirect_uri: REDIRECT_URI, scope: 'openid', state: 'x' });
    const res = await fetch(url, { redirect: 'manual' });
    const location = new URL(res.headers.get('location')!);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('error_description')).toMatch(/PKCE/);
  });
});

function hidden(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  if (!m) throw new Error(`no ${name} in page`);
  return m[1]!;
}

describe('MFA policy "required"', () => {
  it('makes a user without a second factor set one up during sign-in', async () => {
    mfaPolicy = 'required';
    try {
      const config = await discover();
      const browser = new Browser();
      const { page, verifier, state } = await startLogin(browser, config);
      const setup = await browser.go(formAction(page.body), { method: 'POST', form: { email: 'hana@example.com', password: 'hana-password-1' } });
      expect(setup.body).toContain('Set up two-step verification');
      expect(setup.body).toContain('<svg');
      const secret = /<code>([A-Z2-7 ]+)<\/code>/.exec(setup.body)![1]!.replace(/ /g, '');

      const wrong = await browser.go(formAction(setup.body), { method: 'POST', form: { code: '000000' } });
      expect(wrong.status).toBe(400);
      expect(users.findByEmail('hana@example.com')!.totpSecret).toBeNull();

      const code = generateTotp(decodeBase32(secret)!, Math.floor(Date.now() / 1000)).code;
      const codesPage = await browser.go(formAction(wrong.body), { method: 'POST', form: { code } });
      expect([...codesPage.body.matchAll(/<li>[A-Z0-9]{5}-[A-Z0-9]{5}<\/li>/g)]).toHaveLength(10);
      const done = await browser.go(formAction(codesPage.body), { method: 'POST', form: {} });
      const tokens = await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
      expect(tokens.claims()!.amr).toEqual(['pwd', 'otp', 'mfa']);
      expect(users.findByEmail('hana@example.com')!.totpSecret).toBe(secret);
    } finally {
      mfaPolicy = 'optional';
    }
  });
});

describe('account page', () => {
  const at = (path: string) => new URL(path, issuer).toString();

  it('lets a user turn on TOTP, get recovery codes, use one, and sign out', async () => {
    const browser = new Browser();
    // Not signed in: the account page sends the browser through mamori's own sign-in.
    const login = await browser.go(at('/account'));
    expect(login.body).toContain('Sign in');
    const page = await browser.go(formAction(login.body), { method: 'POST', form: { email: 'frank@example.com', password: 'frank-password-1' } });
    expect(page.url).toBe(at('/account'));
    expect(page.body).toContain('frank@example.com');
    expect(page.body).toContain('not set up');
    const csrf = hidden(page.body, 'csrf');

    // Forms without the CSRF token are refused.
    expect((await browser.go(at('/account/totp/start'), { method: 'POST', form: {} })).status).toBe(403);

    const setup = await browser.go(at('/account/totp/start'), { method: 'POST', form: { csrf } });
    expect(setup.body).toContain('<svg');
    const secret = /<code>([A-Z2-7 ]+)<\/code>/.exec(setup.body)![1]!.replace(/ /g, '');
    const wrong = await browser.go(at('/account/totp/confirm'), { method: 'POST', form: { csrf, code: '000000' } });
    expect(wrong.status).toBe(400);
    const code = generateTotp(decodeBase32(secret)!, Math.floor(Date.now() / 1000)).code;
    const done = await browser.go(at('/account/totp/confirm'), { method: 'POST', form: { csrf, code } });
    const codes = [...done.body.matchAll(/<li>([A-Z0-9]{5}-[A-Z0-9]{5})<\/li>/g)].map((m) => m[1]!);
    expect(codes).toHaveLength(10);
    expect(users.findByEmail('frank@example.com')!.totpSecret).toBe(secret);

    // Signing in to an app now asks for a code, and a recovery code works once.
    const config = await discover();
    for (const [i, expected] of [[0, 'ok'], [1, 'reused']] as const) {
      const app = new Browser();
      const { page: appLogin, verifier, state } = await startLogin(app, config);
      const ask = await app.go(formAction(appLogin.body), { method: 'POST', form: { email: 'frank@example.com', password: 'frank-password-1' } });
      expect(ask.body).toContain('recovery codes');
      const res = await app.go(formAction(ask.body), { method: 'POST', form: { code: codes[0]!.toLowerCase() } });
      if (expected === 'ok') {
        const tokens = await client.authorizationCodeGrant(config, new URL(res.url), { pkceCodeVerifier: verifier, expectedState: state });
        expect(tokens.claims()!.amr).toEqual(['pwd', 'otp', 'mfa']);
      } else {
        expect(res.status).toBe(401);
      }
      expect(i).toBeLessThan(2);
    }
    expect(events().some((e) => e.event === 'recovery_code.used' && e.remaining === 9)).toBe(true);

    // Signing out ends the account session and the mamori session.
    const confirm = await browser.go(at('/account/logout'), { method: 'POST', form: { csrf } });
    const action = /<form[^>]*action="([^"]+)"/.exec(confirm.body)![1]!;
    const out = await browser.go(new URL(action, issuer).toString(), { method: 'POST', form: { xsrf: hidden(confirm.body, 'xsrf'), logout: 'yes' } });
    expect(out.url).toBe(at('/account/signed-out'));
    const again = await browser.go(at('/account'));
    expect(again.body).toContain('Sign in');
  });

  it('asks for a current code before removing TOTP', async () => {
    const browser = new Browser();
    const login = await browser.go(at('/account'));
    const ask = await browser.go(formAction(login.body), { method: 'POST', form: { email: 'gina@example.com', password: 'gina-password-1' } });
    const code = generateTotp(decodeBase32(ginaSecret)!, Math.floor(Date.now() / 1000)).code;
    const page = await browser.go(formAction(ask.body), { method: 'POST', form: { code } });
    const csrf = hidden(page.body, 'csrf');
    const refused = await browser.go(at('/account/totp/remove'), { method: 'POST', form: { csrf, code: '000000' } });
    expect(refused.status).toBe(400);
    expect(users.findByEmail('gina@example.com')!.totpSecret).toBe(ginaSecret);
  });
});

describe('passkeys', () => {
  const at = (path: string) => new URL(path, issuer).toString();
  const uidOf = (html: string) => /\/interaction\/([\w-]+)\//.exec(html)![1]!;
  const device = () => new SoftAuthenticator(new URL(issuer).origin);
  const synced = () => new SoftAuthenticator(new URL(issuer).origin, true);
  // Ivy's registered passkeys; once she has one, signing in asks for it.
  const ivyKeys: SoftAuthenticator[] = [];

  async function addPasskey(auth: SoftAuthenticator, name: string) {
    const browser = new Browser();
    const login = await browser.go(at('/account'));
    let page = await browser.go(formAction(login.body), { method: 'POST', form: { email: 'ivy@example.com', password: 'ivy-password-12' } });
    if (ivyKeys.length) {
      const second = await passkeySignIn(browser, page.body, ivyKeys[0]!);
      page = await browser.go(new URL(second.body.location!, issuer).toString());
    }
    const csrf = /data-csrf="([^"]+)"/.exec(page.body)![1]!;
    const noCsrf = await browser.go(at('/account/passkeys/options'), { method: 'POST', json: {} });
    expect(noCsrf.status).toBe(403);
    const options = JSON.parse((await browser.go(at('/account/passkeys/options'), { method: 'POST', json: {}, headers: { 'x-csrf-token': csrf } })).body);
    expect(options.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
    const done = await browser.go(at('/account/passkeys/register'), { method: 'POST', json: { response: auth.register(options), name }, headers: { 'x-csrf-token': csrf } });
    expect(JSON.parse(done.body)).toEqual({ location: '/account' });
    ivyKeys.push(auth);
    return browser;
  }

  async function passkeySignIn(browser: Browser, html: string, auth: SoftAuthenticator, opts: { counter?: number } = {}) {
    const uid = uidOf(html);
    const options = JSON.parse((await browser.go(at(`/interaction/${uid}/passkey-options`), { method: 'POST', json: {} })).body);
    const res = await browser.go(at(`/interaction/${uid}/passkey`), { method: 'POST', json: { response: auth.authenticate(options, opts) } });
    return { options, status: res.status, body: JSON.parse(res.body) as { location?: string; error?: string } };
  }

  async function finish(browser: Browser, location: string, verifier: string, state: string) {
    const config = await discover();
    const done = await browser.go(new URL(location, issuer).toString());
    return client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
  }

  it('adds a passkey on the account page and signs in with it without an email', async () => {
    const laptop = device();
    const browser = await addPasskey(laptop, 'Work laptop');
    expect((await browser.go(at('/account'))).body).toContain('Work laptop');

    const app = new Browser();
    const { page, verifier, state } = await startLogin(app, await discover());
    expect(page.body).toContain('Sign in with a passkey');
    const result = await passkeySignIn(app, page.body, laptop);
    expect(result.options.allowCredentials).toEqual([]);
    const tokens = await finish(app, result.body.location!, verifier, state);
    expect(tokens.claims()!.amr).toEqual(['hwk', 'mfa']);
    expect(tokens.claims()!.email).toBe('ivy@example.com');
  });

  it('asks for the passkey after the password, and reports a synced passkey as swk', async () => {
    const phone = synced();
    await addPasskey(phone, 'Phone');
    const app = new Browser();
    const { page, verifier, state } = await startLogin(app, await discover());
    const second = await app.go(formAction(page.body), { method: 'POST', form: { email: 'ivy@example.com', password: 'ivy-password-12' } });
    expect(second.body).toContain('Use your passkey');
    const result = await passkeySignIn(app, second.body, phone);
    // After a password, only this user's passkeys are offered.
    expect(result.options.allowCredentials.map((c: { id: string }) => c.id)).toContain(phone.id);
    const tokens = await finish(app, result.body.location!, verifier, state);
    expect(tokens.claims()!.amr).toEqual(['pwd', 'swk', 'mfa']);
  });

  it('refuses a passkey whose sign counter went backwards', async () => {
    const key = device();
    await addPasskey(key, 'Security key');
    const first = new Browser();
    const { page } = await startLogin(first, await discover());
    expect((await passkeySignIn(first, page.body, key, { counter: 10 })).status).toBe(200);

    const clone = new Browser();
    const { page: again } = await startLogin(clone, await discover());
    const result = await passkeySignIn(clone, again.body, key, { counter: 5 });
    expect(result.status).toBe(400);
    expect(events().some((e) => e.event === 'passkey.counter_regressed')).toBe(true);
  });

  it('does not accept a passkey that was never registered', async () => {
    const app = new Browser();
    const { page } = await startLogin(app, await discover());
    const stranger = device();
    stranger.userHandle = 'nobody';
    const result = await passkeySignIn(app, page.body, stranger);
    expect(result.status).toBe(400);
  });
});
