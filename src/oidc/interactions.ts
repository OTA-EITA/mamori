import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { decodeBase32 } from '../totp/base32.js';
import { verifyTotp } from '../totp/totp.js';
import type { UserStore } from '../store/users.js';
import { errorPage, loginPage, totpPage } from './pages.js';

const MAX_FAILURES = 10;
const LOCK_SECONDS = 15 * 60;

// Failed sign-ins per email, kept in memory. Enough for one instance; it
// resets on restart, which is acceptable for a lock of 15 minutes.
class FailureCounter {
  private readonly entries = new Map<string, { count: number; until: number }>();

  isLocked(key: string, now: number): boolean {
    const e = this.entries.get(key);
    return e !== undefined && e.count >= MAX_FAILURES && e.until > now;
  }

  fail(key: string, now: number): void {
    const e = this.entries.get(key);
    const count = e && e.until > now ? e.count + 1 : 1;
    this.entries.set(key, { count, until: now + LOCK_SECONDS });
  }

  reset(key: string): void {
    this.entries.delete(key);
  }
}

async function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > 16 * 1024) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
}

function send(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
  });
  res.end(html);
}

export function interactionHandler(provider: Provider, users: UserStore, now: () => number = () => Math.floor(Date.now() / 1000)) {
  const failures = new FailureCounter();
  // Users who passed the password step and still owe a TOTP code, keyed by interaction uid.
  const pendingTotp = new Map<string, { accountId: string; expires: number }>();

  async function finishLogin(req: IncomingMessage, res: ServerResponse, accountId: string, amr: string[]) {
    await provider.interactionFinished(req, res, { login: { accountId, amr } }, { mergeWithLastSubmission: false });
  }

  // mamori is meant for first-party apps that the admin registered, so the
  // requested scopes are granted without a consent screen.
  async function grantConsent(req: IncomingMessage, res: ServerResponse) {
    const details = await provider.interactionDetails(req, res);
    const { prompt, params, session, grantId } = details;
    const grant = grantId
      ? await provider.Grant.find(grantId)
      : new provider.Grant({ accountId: session!.accountId, clientId: params.client_id as string });
    if (!grant) throw new Error('grant not found');
    const missing = prompt.details as { missingOIDCScope?: string[]; missingOIDCClaims?: string[] };
    if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
    if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
    await provider.interactionFinished(req, res, { consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: true });
  }

  return async function handle(req: IncomingMessage, res: ServerResponse, uid: string, action: string | undefined): Promise<void> {
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== uid) return send(res, 400, errorPage('This sign-in link is not valid any more. Start again from the app.'));
    const client = await provider.Client.find(details.params.client_id as string);
    const clientName = client?.clientName ?? (details.params.client_id as string);

    if (req.method === 'GET' && action === undefined) {
      if (details.prompt.name === 'consent') return grantConsent(req, res);
      return send(res, 200, loginPage(uid, { client: clientName }));
    }

    if (req.method === 'POST' && action === 'login') {
      const form = await readForm(req);
      const email = (form.get('email') ?? '').trim().toLowerCase();
      if (failures.isLocked(email, now())) {
        return send(res, 429, loginPage(uid, { client: clientName, email, error: 'Too many failed attempts. Try again in 15 minutes.' }));
      }
      const user = await users.authenticate(email, form.get('password') ?? '');
      if (!user) {
        failures.fail(email, now());
        return send(res, 401, loginPage(uid, { client: clientName, email, error: 'The email or password is not correct.' }));
      }
      if (user.totpSecret) {
        pendingTotp.set(uid, { accountId: user.id, expires: now() + 5 * 60 });
        return send(res, 200, totpPage(uid, {}));
      }
      failures.reset(email);
      return finishLogin(req, res, user.id, ['pwd']);
    }

    if (req.method === 'POST' && action === 'totp') {
      const pending = pendingTotp.get(uid);
      if (!pending || pending.expires <= now()) {
        pendingTotp.delete(uid);
        return send(res, 400, loginPage(uid, { client: clientName, error: 'Sign in again.' }));
      }
      const user = users.findById(pending.accountId);
      const secret = user?.totpSecret ? decodeBase32(user.totpSecret) : null;
      const form = await readForm(req);
      const result = secret
        ? verifyTotp(secret, (form.get('code') ?? '').trim(), now(), { ...(user!.totpLastCounter !== null ? { lastUsedCounter: user!.totpLastCounter } : {}) })
        : { ok: false };
      if (!user || !result.ok || result.counter === undefined) {
        failures.fail(user?.email ?? pending.accountId, now());
        if (user && failures.isLocked(user.email, now())) pendingTotp.delete(uid);
        return send(res, 401, totpPage(uid, { error: 'The code is not correct.' }));
      }
      pendingTotp.delete(uid);
      users.setTotpLastCounter(user.id, result.counter);
      failures.reset(user.email);
      return finishLogin(req, res, user.id, ['pwd', 'otp']);
    }

    send(res, 404, errorPage('Not found.'));
  };
}
