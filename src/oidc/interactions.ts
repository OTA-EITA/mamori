import type { IncomingMessage, ServerResponse } from 'node:http';
import type Provider from 'oidc-provider';
import { buildOtpauthUri, decodeBase32, generateTotpSecret } from '../totp/base32.js';
import { renderSVG } from 'uqr';
import { verifyTotp } from '../totp/totp.js';
import type { AuditLog } from '../audit/audit.js';
import { looksLikeRecoveryCode, type RecoveryCodes } from '../console/recovery.js';
import type { UserStore } from '../store/users.js';
import { clientIp } from '../clientIp.js';
import { SignInThrottle } from './throttle.js';
import { errorPage, loginPage, mfaSetupDonePage, mfaSetupPage, secondFactorPage } from './pages.js';
import { readForm, readJson, send, sendJson, SCRIPT_CSP } from '../http.js';
import type { PasskeyStore } from '../store/passkeys.js';
import { passkeyAmr, type WebAuthn } from '../passkeys/webauthn.js';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';

export type MfaPolicy = 'optional' | 'required';

// RFC 8176 values. "mfa" is added whenever two independent factors were used,
// so apps can check one value.
const PASSWORD_AMR = ['pwd'];
const OTP_AMR = ['pwd', 'otp', 'mfa'];

export interface InteractionOptions {
  audit?: AuditLog;
  recovery?: RecoveryCodes;
  // With "required", a user without a second factor sets one up during sign-in.
  mfaPolicy?: () => MfaPolicy;
  // Name shown in authenticator apps, for the setup step.
  totpIssuer?: string;
  passkeys?: PasskeyStore;
  webauthn?: WebAuthn;
  trustProxy?: boolean;
  now?: () => number;
  sleep?: (seconds: number) => Promise<void>;
}

const realSleep = (seconds: number) => new Promise<void>((resolve) => setTimeout(resolve, seconds * 1000));

export function interactionHandler(provider: Provider, users: UserStore, opts: InteractionOptions = {}) {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const sleep = opts.sleep ?? realSleep;
  const throttle = new SignInThrottle(now);
  const audit = opts.audit;
  // Users who passed the password step and still owe a second factor (TOTP
  // code, recovery code or passkey), keyed by interaction uid.
  const pendingSecond = new Map<string, { accountId: string; expires: number }>();
  // Users who passed the password step and must set up a second factor first.
  const pendingSetup = new Map<string, { accountId: string; secret: string; expires: number }>();
  // Users who finished the setup and are looking at their recovery codes.
  const pendingContinue = new Map<string, { accountId: string; expires: number }>();
  const mfaPolicy = opts.mfaPolicy ?? (() => 'optional' as const);
  // WebAuthn challenges handed out to this interaction.
  const challenges = new Map<string, { challenge: string; expires: number }>();
  const passkeysOf = (userId: string) => opts.passkeys?.listByUser(userId) ?? [];
  const html = (status: number, page: string, res: ServerResponse) => send(res, status, page, { 'content-security-policy': SCRIPT_CSP });
  const setupQr = (email: string, secret: string) =>
    renderSVG(buildOtpauthUri({ issuer: opts.totpIssuer ?? new URL(provider.issuer).hostname, account: email, secret }));

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
    const ip = clientIp(req, opts.trustProxy ?? false);
    const clientName = client?.clientName ?? (details.params.client_id as string);
    const userAgent = req.headers['user-agent'];
    const log = (event: string, email: string, extra: Record<string, unknown> = {}, id?: string) =>
      audit?.write({ event, actor: { type: 'user', email, ...(id ? { id } : {}) }, client_id: details.params.client_id as string, ip, ...(userAgent ? { user_agent: userAgent } : {}), ...extra });

    if (req.method === 'GET' && action === undefined) {
      if (details.prompt.name === 'consent') return grantConsent(req, res);
      return html(200, loginPage(uid, { client: clientName, passkeys: !!opts.webauthn }), res);
    }

    if (req.method === 'POST' && action === 'login') {
      const form = await readForm(req);
      const email = (form.get('email') ?? '').trim().toLowerCase();
      if (throttle.isLocked(email, ip)) {
        log('sign_in.throttled', email);
        return send(res, 429, loginPage(uid, { client: clientName, email, error: 'Too many failed attempts. Try again in 15 minutes.' }));
      }
      await sleep(throttle.delaySeconds(email));
      const user = await users.authenticate(email, form.get('password') ?? '');
      if (!user) {
        throttle.fail(email, ip);
        log('sign_in.failed', email, { reason: 'wrong_password' });
        return send(res, 401, loginPage(uid, { client: clientName, email, error: 'The email or password is not correct.' }));
      }
      const hasPasskey = passkeysOf(user.id).length > 0;
      if (user.totpSecret || hasPasskey) {
        pendingSecond.set(uid, { accountId: user.id, expires: now() + 5 * 60 });
        return html(200, secondFactorPage(uid, { code: user.totpSecret !== null, passkey: hasPasskey && !!opts.webauthn }), res);
      }
      throttle.succeed(email, ip);
      if (mfaPolicy() === 'required') {
        const secret = generateTotpSecret();
        pendingSetup.set(uid, { accountId: user.id, secret, expires: now() + 10 * 60 });
        log('mfa.setup_required', user.email, {}, user.id);
        return send(res, 200, mfaSetupPage(uid, { qrSvg: setupQr(user.email, secret), secret }));
      }
      users.setLastSignIn(user.id, new Date(now() * 1000));
      log('sign_in.succeeded', user.email, { amr: PASSWORD_AMR }, user.id);
      return finishLogin(req, res, user.id, PASSWORD_AMR);
    }

    if (req.method === 'POST' && action === 'setup') {
      const pending = pendingSetup.get(uid);
      const user = pending ? users.findById(pending.accountId) : undefined;
      if (!pending || pending.expires <= now() || !user || user.disabled) {
        pendingSetup.delete(uid);
        return send(res, 400, loginPage(uid, { client: clientName, error: 'Sign in again.' }));
      }
      const form = await readForm(req);
      const result = verifyTotp(decodeBase32(pending.secret)!, (form.get('code') ?? '').trim(), now());
      if (!result.ok || result.counter === undefined) {
        return send(res, 400, mfaSetupPage(uid, { qrSvg: setupQr(user.email, pending.secret), secret: pending.secret, error: 'That code is not correct. Check the time on your phone and try again.' }));
      }
      pendingSetup.delete(uid);
      users.setTotpSecret(user.id, pending.secret);
      users.setTotpLastCounter(user.id, result.counter);
      log('totp.added', user.email, { during: 'sign_in' }, user.id);
      const codes = opts.recovery?.generate(user.id) ?? [];
      if (codes.length) log('recovery_codes.generated', user.email, { during: 'sign_in' }, user.id);
      users.setLastSignIn(user.id, new Date(now() * 1000));
      log('sign_in.succeeded', user.email, { amr: OTP_AMR }, user.id);
      pendingContinue.set(uid, { accountId: user.id, expires: now() + 10 * 60 });
      return send(res, 200, mfaSetupDonePage(uid, { codes }));
    }

    if (req.method === 'POST' && action === 'continue') {
      const pending = pendingContinue.get(uid);
      pendingContinue.delete(uid);
      if (!pending || pending.expires <= now()) return send(res, 400, loginPage(uid, { client: clientName, error: 'Sign in again.' }));
      return finishLogin(req, res, pending.accountId, OTP_AMR);
    }

    if (req.method === 'POST' && action === 'totp') {
      const pending = pendingSecond.get(uid);
      if (!pending || pending.expires <= now()) {
        pendingSecond.delete(uid);
        return send(res, 400, loginPage(uid, { client: clientName, error: 'Sign in again.' }));
      }
      const user = users.findById(pending.accountId);
      const key = (user?.email ?? pending.accountId).toLowerCase();
      // The same throttling as the password step. Without it, someone who has
      // the password could try codes as fast as the server answers.
      if (throttle.isLocked(key, ip)) {
        pendingSecond.delete(uid);
        log('sign_in.throttled', key, { step: 'otp' }, user?.id);
        return send(res, 429, loginPage(uid, { client: clientName, error: 'Too many failed attempts. Try again in 15 minutes.' }));
      }
      await sleep(throttle.delaySeconds(key));
      const secret = user?.totpSecret ? decodeBase32(user.totpSecret) : null;
      const form = await readForm(req);
      const input = (form.get('code') ?? '').trim();
      // A recovery code can stand in for the TOTP code. It is one-time too, so
      // the ID token reports it as "otp"; the audit log tells them apart.
      if (user && opts.recovery && looksLikeRecoveryCode(input) && opts.recovery.use(user.id, input)) {
        pendingSecond.delete(uid);
        throttle.succeed(user.email.toLowerCase(), ip);
        users.setLastSignIn(user.id, new Date(now() * 1000));
        log('recovery_code.used', user.email, { remaining: opts.recovery.remaining(user.id) }, user.id);
        log('sign_in.succeeded', user.email, { amr: OTP_AMR, method: 'recovery_code' }, user.id);
        return finishLogin(req, res, user.id, OTP_AMR);
      }
      const result = secret
        ? verifyTotp(secret, input, now(), { ...(user!.totpLastCounter !== null ? { lastUsedCounter: user!.totpLastCounter } : {}) })
        : { ok: false };
      if (!user || !result.ok || result.counter === undefined) {
        throttle.fail(key, ip);
        log('mfa.challenge_failed', key, { method: 'otp' }, user?.id);
        if (throttle.isLocked(key, ip)) pendingSecond.delete(uid);
        return html(401, secondFactorPage(uid, { code: user?.totpSecret != null, passkey: !!user && passkeysOf(user.id).length > 0 && !!opts.webauthn, error: 'The code is not correct.' }), res);
      }
      pendingSecond.delete(uid);
      users.setTotpLastCounter(user.id, result.counter);
      throttle.succeed(user.email.toLowerCase(), ip);
      users.setLastSignIn(user.id, new Date(now() * 1000));
      log('sign_in.succeeded', user.email, { amr: OTP_AMR }, user.id);
      return finishLogin(req, res, user.id, OTP_AMR);
    }

    if (req.method === 'POST' && action === 'passkey-options' && opts.webauthn) {
      // After a password, only that user's passkeys; otherwise any passkey of
      // this site (usernameless sign-in).
      const second = pendingSecond.get(uid);
      const options = await opts.webauthn.authenticationOptions(second ? passkeysOf(second.accountId) : []);
      challenges.set(uid, { challenge: options.challenge, expires: now() + 5 * 60 });
      return sendJson(res, 200, options);
    }

    if (req.method === 'POST' && action === 'passkey' && opts.webauthn && opts.passkeys) {
      const issued = challenges.get(uid);
      challenges.delete(uid);
      const body = (await readJson(req)) as { response?: AuthenticationResponseJSON };
      const response = body.response;
      const passkey = response?.id ? opts.passkeys.find(response.id) : undefined;
      const second = pendingSecond.get(uid);
      const user = passkey ? users.findById(passkey.userId) : undefined;
      if (!issued || issued.expires <= now() || !response || !passkey || !user || user.disabled || (second && second.accountId !== passkey.userId)) {
        log(second ? 'mfa.challenge_failed' : 'sign_in.failed', user?.email ?? '', { method: 'passkey', reason: 'unknown_passkey' }, user?.id);
        return sendJson(res, 400, { error: 'This passkey cannot sign in here. Try again or use your password.' });
      }
      let verified: { counter: number; backedUp: boolean } | undefined;
      try {
        verified = await opts.webauthn.verifyAuthentication(response, issued.challenge, passkey);
      } catch (err) {
        const regressed = err instanceof Error && /counter/i.test(err.message);
        if (regressed) log('passkey.counter_regressed', user.email, { passkey: passkey.name }, user.id);
        log(second ? 'mfa.challenge_failed' : 'sign_in.failed', user.email, { method: 'passkey', reason: regressed ? 'counter_regressed' : 'invalid' }, user.id);
        return sendJson(res, 400, { error: 'This passkey did not work.' });
      }
      if (!verified) return sendJson(res, 400, { error: 'This passkey did not work.' });
      opts.passkeys.recordUse(passkey.id, verified.counter, verified.backedUp);
      pendingSecond.delete(uid);
      // A passkey with user verification is two factors on its own.
      const amr = second ? ['pwd', passkeyAmr(verified.backedUp), 'mfa'] : [passkeyAmr(verified.backedUp), 'mfa'];
      throttle.succeed(user.email.toLowerCase(), ip);
      users.setLastSignIn(user.id, new Date(now() * 1000));
      log('sign_in.succeeded', user.email, { amr, method: 'passkey' }, user.id);
      const location = await provider.interactionResult(req, res, { login: { accountId: user.id, amr } }, { mergeWithLastSubmission: false });
      return sendJson(res, 200, { location });
    }

    send(res, 404, errorPage('Not found.'));
  };
}
