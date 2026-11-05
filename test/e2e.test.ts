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

const REDIRECT_URI = 'http://127.0.0.1:9/callback';

let server: Server;
let issuer: string;
let users: UserStore;
const totpSecret = generateTotpSecret();

// A tiny browser: keeps cookies and follows redirects until it reaches a page
// or the client's redirect_uri.
class Browser {
  private readonly cookies = new Map<string, string>();

  async go(url: string, init: { method?: string; form?: Record<string, string> } = {}): Promise<{ url: string; status: number; body: string }> {
    let current = url;
    let method = init.method ?? 'GET';
    let body: string | undefined = init.form ? new URLSearchParams(init.form).toString() : undefined;
    for (let hops = 0; hops < 20; hops++) {
      if (current.startsWith(REDIRECT_URI)) return { url: current, status: 0, body: '' };
      const headers: Record<string, string> = { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ') };
      if (body) headers['content-type'] = 'application/x-www-form-urlencoded';
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

async function startLogin(browser: Browser, config: client.Configuration) {
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile',
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    state,
  });
  return { page: await browser.go(url.toString()), verifier, state };
}

const sleeps: number[] = [];

beforeAll(async () => {
  const db = openDatabase(':memory:');
  users = new UserStore(db);
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
      clients: [{ client_id: 'app', client_secret: 'app-secret', redirect_uris: [REDIRECT_URI], client_name: 'Test App' }],
    },
    db,
    users,
  );
  // No real waiting for the throttling delays in tests; record them instead.
  handler = createRequestHandler(provider, users, { sleep: async (seconds) => void sleeps.push(seconds) });
  await users.create({ email: 'alice@example.com', name: 'Alice', password: 'alice-password-1' });
  const carol = await users.create({ email: 'carol@example.com', name: 'Carol', password: 'carol-password' });
  users.setDisabled(carol.id, true);
  await users.create({ email: 'dave@example.com', name: 'Dave', password: 'dave-password-1' });
  const bob = await users.create({ email: 'bob@example.com', name: 'Bob', password: 'bob-password-12' });
  users.setTotpSecret(bob.id, totpSecret);
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
    expect(totp.body).toContain('Verification code');

    const wrong = await browser.go(formAction(totp.body), { method: 'POST', form: { code: '000000' } });
    expect(wrong.status).toBe(401);

    const code = generateTotp(decodeBase32(totpSecret)!, Math.floor(Date.now() / 1000)).code;
    const done = await browser.go(formAction(wrong.body), { method: 'POST', form: { code } });
    expect(done.url.startsWith(REDIRECT_URI)).toBe(true);
    const tokens = await client.authorizationCodeGrant(config, new URL(done.url), { pkceCodeVerifier: verifier, expectedState: state });
    expect(tokens.claims()!.amr).toEqual(['pwd', 'otp']);
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
    expect(res.body).toContain('Verification code');
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

  it('refuses an authorization request without PKCE', async () => {
    const config = await discover();
    const url = client.buildAuthorizationUrl(config, { redirect_uri: REDIRECT_URI, scope: 'openid', state: 'x' });
    const res = await fetch(url, { redirect: 'manual' });
    const location = new URL(res.headers.get('location')!);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('error_description')).toMatch(/PKCE/);
  });
});
