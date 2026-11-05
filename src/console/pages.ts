const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)}</title>
<style>
  body { font-family: system-ui, sans-serif; background: #f4f5f7; margin: 0; }
  main { max-width: 30rem; margin: 6vh auto; background: #fff; padding: 2rem; border-radius: 8px; }
  section { border-top: 1px solid #e3e5e8; margin-top: 1.5rem; padding-top: 1rem; }
  label { display: block; margin-top: 1rem; font-size: .9rem; }
  input { width: 100%; box-sizing: border-box; padding: .6rem; margin-top: .3rem; font-size: 1rem; }
  button { margin-top: 1rem; padding: .6rem 1rem; font-size: 1rem; }
  .muted { color: #5f6368; font-size: .9rem; }
  .error { color: #b00020; }
  .notice { background: #e8f0fe; padding: .7rem 1rem; border-radius: 6px; }
  .qr svg { width: 12rem; height: 12rem; }
  code, .codes { font-family: ui-monospace, monospace; }
  .codes { columns: 2; padding-left: 1.2rem; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${escape(csrf)}">`;

export interface AccountView {
  name: string;
  email: string;
  hasTotp: boolean;
  recoveryCodesLeft: number;
  csrf: string;
  // Undefined when passkeys are not available on this server.
  passkeys?: { id: string; name: string; createdAt: string; lastUsedAt: string | null }[];
  notice?: string;
  error?: string;
}

export function accountPage(v: AccountView): string {
  const totp = v.hasTotp
    ? `<p>Authenticator app: <strong>set up</strong></p>
<form method="post" action="/account/totp/remove">${csrfField(v.csrf)}
  <label>To remove it, enter a code from the app<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
  <button type="submit">Remove authenticator app</button>
</form>`
    : `<p>Authenticator app: <strong>not set up</strong></p>
<form method="post" action="/account/totp/start">${csrfField(v.csrf)}<button type="submit">Set up an authenticator app</button></form>`;
  const recovery = `<p>Recovery codes left: <strong>${v.recoveryCodesLeft}</strong></p>
<p class="muted">Each code signs you in once if you lose your phone. Making new codes replaces the old ones.</p>
<form method="post" action="/account/recovery-codes">${csrfField(v.csrf)}<button type="submit">Make new recovery codes</button></form>`;
  return page(
    'Your account',
    `<h1>Your account</h1>
${v.notice ? `<p class="notice">${escape(v.notice)}</p>` : ''}
${v.error ? `<p class="error">${escape(v.error)}</p>` : ''}
<p>${escape(v.name)}<br><span class="muted">${escape(v.email)}</span></p>
${v.passkeys ? `<section><h2>Passkeys</h2>${passkeySection(v.passkeys, v.csrf)}</section>` : ''}
<section><h2>Two-step verification</h2>${totp}</section>
<section><h2>Recovery codes</h2>${recovery}</section>
<section><form method="post" action="/account/logout">${csrfField(v.csrf)}<button type="submit">Sign out</button></form></section>`,
  );
}

const day = (iso: string) => iso.slice(0, 10);

function passkeySection(list: NonNullable<AccountView['passkeys']>, csrf: string): string {
  const items = list.length
    ? `<ul>${list
        .map(
          (p) => `<li>${escape(p.name)} <span class="muted">added ${day(p.createdAt)}${p.lastUsedAt ? `, last used ${day(p.lastUsedAt)}` : ', not used yet'}</span>
<form method="post" action="/account/passkeys/remove">${csrfField(csrf)}<input type="hidden" name="id" value="${escape(p.id)}"><button type="submit">Remove</button></form></li>`,
        )
        .join('')}</ul>`
    : '<p class="muted">No passkeys yet. A passkey signs you in with your fingerprint, face or device PIN, without a password.</p>';
  return `${items}
<p id="passkey-error" class="error" hidden></p>
<label>Name for the new passkey<input id="passkey-name" maxlength="60" placeholder="e.g. Work laptop"></label>
<button type="button" hidden data-passkey="register" data-options="/account/passkeys/options" data-verify="/account/passkeys/register" data-csrf="${escape(csrf)}">Add a passkey</button>
<script src="/assets/passkey.js" defer></script>`;
}

export function totpSetupPage(v: { qrSvg: string; secret: string; csrf: string; error?: string }): string {
  const grouped = v.secret.match(/.{1,4}/g)!.join(' ');
  return page(
    'Set up an authenticator app',
    `<h1>Set up an authenticator app</h1>
<p>Scan this code with Google Authenticator, Microsoft Authenticator or a similar app.</p>
<div class="qr">${v.qrSvg}</div>
<p class="muted">Cannot scan it? Enter this key in the app instead:<br><code>${escape(grouped)}</code></p>
${v.error ? `<p class="error">${escape(v.error)}</p>` : ''}
<form method="post" action="/account/totp/confirm">${csrfField(v.csrf)}
  <label>Then enter the 6-digit code the app shows<input name="code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required autofocus></label>
  <button type="submit">Turn on</button>
</form>
<p><a href="/account">Cancel</a></p>`,
  );
}

export function recoveryCodesPage(v: { codes: string[]; intro: string }): string {
  return page(
    'Recovery codes',
    `<h1>Recovery codes</h1>
<p class="notice">${escape(v.intro)}</p>
<p>Keep these somewhere safe, such as a password manager. They are shown only now. Each one works once.</p>
<ol class="codes">${v.codes.map((c) => `<li>${escape(c)}</li>`).join('')}</ol>
<p><a href="/account">Back to your account</a></p>`,
  );
}

export function signedOutPage(): string {
  return page('Signed out', `<h1>Signed out</h1><p>You have signed out.</p><p><a href="/account">Sign in again</a></p>`);
}

export function logoutConfirmPage(form: string): string {
  // oidc-provider builds the form (with its own hidden fields) and expects it
  // to be submitted; the button submits it.
  return page('Sign out', `<h1>Sign out</h1><p>Sign out of every app that uses this sign-in?</p>${form}<button type="submit" form="op.logoutForm" name="logout" value="yes">Sign out</button>`);
}

export function setupPage(v: { email: string; error?: string }): string {
  return page(
    'Choose a password',
    `<h1>Choose a password</h1>
<p>${escape(v.email)}</p>
${v.error ? `<p class="error">${escape(v.error)}</p>` : ''}
<form method="post">
  <input type="hidden" name="username" autocomplete="username" value="${escape(v.email)}">
  <label>New password (12 characters or more)<input type="password" name="password" autocomplete="new-password" minlength="12" required autofocus></label>
  <label>Type it again<input type="password" name="confirm" autocomplete="new-password" minlength="12" required></label>
  <button type="submit">Save and sign in</button>
</form>`,
  );
}

export function setupLinkInvalidPage(): string {
  return page('Link not valid', '<h1>This link does not work</h1><p>It was already used or is more than 24 hours old. Ask your administrator for a new one.</p>');
}
