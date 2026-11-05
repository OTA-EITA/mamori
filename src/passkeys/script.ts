// The only script mamori serves, at /assets/passkey.js. Pages that use it send
// `script-src 'self'`; there is no inline script anywhere.
//
// <button data-passkey="register" data-options="URL" data-verify="URL" data-csrf="TOKEN">
// <button data-passkey="sign-in" data-options="URL" data-verify="URL">
// The verify endpoint answers JSON: { "location": "..." } or { "error": "..." }.
export const PASSKEY_SCRIPT = `'use strict';
(function () {
  var supported = window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON && PublicKeyCredential.parseRequestOptionsFromJSON;
  function show(message) {
    var el = document.getElementById('passkey-error');
    if (el) { el.textContent = message; el.hidden = false; }
  }
  async function post(url, body, csrf) {
    var headers = { 'content-type': 'application/json' };
    if (csrf) headers['x-csrf-token'] = csrf;
    var res = await fetch(url, { method: 'POST', headers: headers, credentials: 'same-origin', body: JSON.stringify(body || {}) });
    return res.json();
  }
  document.querySelectorAll('[data-passkey]').forEach(function (button) {
    if (!supported) { button.hidden = true; return; }
    button.hidden = false;
    button.addEventListener('click', async function () {
      button.disabled = true;
      try {
        var csrf = button.dataset.csrf;
        var options = await post(button.dataset.options, {}, csrf);
        if (options.error) throw new Error(options.error);
        var credential = button.dataset.passkey === 'register'
          ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
          : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
        var nameInput = document.getElementById('passkey-name');
        var result = await post(button.dataset.verify, { response: credential.toJSON(), name: nameInput ? nameInput.value : '' }, csrf);
        if (result.error) throw new Error(result.error);
        window.location.assign(result.location);
      } catch (err) {
        show(err && err.name === 'NotAllowedError' ? 'The passkey request was cancelled or timed out.' : (err && err.message) || 'The passkey did not work.');
        button.disabled = false;
      }
    });
  });
})();
`;
