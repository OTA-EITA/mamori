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
  main { max-width: 22rem; margin: 10vh auto; background: #fff; padding: 2rem; border-radius: 8px; }
  label { display: block; margin-top: 1rem; font-size: .9rem; }
  input { width: 100%; box-sizing: border-box; padding: .6rem; margin-top: .3rem; font-size: 1rem; }
  button { width: 100%; margin-top: 1.5rem; padding: .7rem; font-size: 1rem; }
  button.secondary { margin-top: .5rem; }
  .error { color: #b00020; }
  .muted { color: #5f6368; font-size: .9rem; }
  .qr svg { width: 12rem; height: 12rem; }
  code, .codes { font-family: ui-monospace, monospace; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

const passkeyScript = '<script src="/assets/passkey.js" defer></script>';
const passkeyError = '<p id="passkey-error" class="error" hidden></p>';

// The passkey button is hidden until the script finds WebAuthn support.
function passkeyButton(uid: string, label: string): string {
  return `<button type="button" class="secondary" hidden data-passkey="sign-in" data-options="/interaction/${escape(uid)}/passkey-options" data-verify="/interaction/${escape(uid)}/passkey">${escape(label)}</button>`;
}

export function loginPage(uid: string, opts: { client: string; email?: string; error?: string; passkeys?: boolean }): string {
  return page(
    'Sign in',
    `<h1>Sign in</h1>
<p>to ${escape(opts.client)}</p>
${opts.error ? `<p class="error">${escape(opts.error)}</p>` : ''}
${opts.passkeys ? `${passkeyError}${passkeyButton(uid, 'Sign in with a passkey')}` : ''}
<form method="post" action="/interaction/${escape(uid)}/login">
  <label>Email<input type="email" name="email" autocomplete="username webauthn" required autofocus value="${escape(opts.email ?? '')}"></label>
  <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
  <button type="submit">Sign in</button>
</form>
${opts.passkeys ? passkeyScript : ''}`,
  );
}

// The second step after a password: a code from the authenticator app (or a
// recovery code), or a passkey, whichever the user has.
export function secondFactorPage(uid: string, opts: { code: boolean; passkey: boolean; error?: string }): string {
  const code = `<p>Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
<form method="post" action="/interaction/${escape(uid)}/totp">
  <label>Code<input name="code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" required autofocus></label>
  <button type="submit">Verify</button>
</form>`;
  const recoveryOnly = `<p>If you cannot use your passkey, enter one of your recovery codes.</p>
<form method="post" action="/interaction/${escape(uid)}/totp">
  <label>Recovery code<input name="code" autocapitalize="characters" spellcheck="false" required></label>
  <button type="submit">Verify</button>
</form>`;
  return page(
    'Verify it is you',
    `<h1>Verify it is you</h1>
${opts.error ? `<p class="error">${escape(opts.error)}</p>` : ''}
${opts.passkey ? `${passkeyError}${passkeyButton(uid, 'Use your passkey')}` : ''}
${opts.code ? code : recoveryOnly}
${opts.passkey ? passkeyScript : ''}`,
  );
}

export function mfaSetupPage(uid: string, opts: { qrSvg: string; secret: string; error?: string }): string {
  const grouped = opts.secret.match(/.{1,4}/g)!.join(' ');
  return page(
    'Set up two-step verification',
    `<h1>Set up two-step verification</h1>
<p>Your organization requires a second step when you sign in. Scan this code with Google Authenticator, Microsoft Authenticator or a similar app.</p>
<div class="qr">${opts.qrSvg}</div>
<p class="muted">Cannot scan it? Enter this key in the app instead:<br><code>${escape(grouped)}</code></p>
${opts.error ? `<p class="error">${escape(opts.error)}</p>` : ''}
<form method="post" action="/interaction/${escape(uid)}/setup">
  <label>Then enter the 6-digit code the app shows<input name="code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required autofocus></label>
  <button type="submit">Turn on</button>
</form>`,
  );
}

export function mfaSetupDonePage(uid: string, opts: { codes: string[] }): string {
  return page(
    'Recovery codes',
    `<h1>Two-step verification is on</h1>
${
  opts.codes.length
    ? `<p>If you lose your phone, sign in with one of these recovery codes instead. Keep them somewhere safe, such as a password manager. They are shown only now, and each works once.</p>
<ol class="codes">${opts.codes.map((c) => `<li>${escape(c)}</li>`).join('')}</ol>`
    : ''
}
<form method="post" action="/interaction/${escape(uid)}/continue">
  <button type="submit">I saved them, continue</button>
</form>`,
  );
}

export function errorPage(message: string): string {
  return page('Error', `<h1>Something went wrong</h1><p>${escape(message)}</p>`);
}
