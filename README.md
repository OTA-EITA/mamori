# mamori

A small, self-hosted identity provider for teams of 10 to 100 people: OpenID Connect single sign-on, TOTP and passkeys, and (planned) SCIM and provisioning connectors for the SaaS tools Japanese companies use.

mamori runs as one Node.js process with one SQLite file. It builds on the OpenID Certified [`oidc-provider`](https://github.com/panva/node-oidc-provider) library rather than implementing the protocol itself.

**Status: early development.** Not ready for production use.

See [docs/design.md](docs/design.md) for the scope and roadmap.

## What works today

- OpenID Connect provider with the authorization code flow. PKCE (S256) is required for every client.
- Sign-in with email and password, plus TOTP for users who have it set up. The ID token's `amr` says which (`["pwd"]`, or `["pwd", "otp", "mfa"]` when a second factor was used; check for `mfa`).
- MFA policy: with `"mfa": "required"` (the default for new installs), a user without a second factor sets up an authenticator app and saves recovery codes during sign-in, and cannot skip it. Databases upgraded from v0.1 default to `"optional"` and log a warning.
- Failed sign-ins are throttled: an IP is refused for an email after 10 failures in 15 minutes, and every failure after the fifth slows down further attempts for that email. The account itself is never locked. Disabled users cannot sign in, and disabling a user signs them out of every app.
- Passwords are hashed with scrypt. TOTP secrets, which the server has to read back and so cannot hash, are encrypted with AES-256-GCM using a key in a separate file (`mamori.key`, created on first start). Signing keys and cookie keys are generated on first start and kept in the SQLite file.
- Account page at `/account`: people set up an authenticator app themselves (QR code, confirmed with a code), remove it (only with a current code) and make recovery codes, ten one-time codes shown once and stored as keyed hashes. A recovery code works in place of the TOTP code when signing in. The page signs in through mamori's own OpenID Connect flow as the built-in `mamori-console` client; its session ends after 30 idle minutes or 8 hours, and every form carries a CSRF token.
- Groups: apps that request the `groups` scope get a `groups` claim with the user's group names in the ID token and userinfo, for mapping groups to roles. Manage them with `mamori-admin group ...`.
- Audit log: sign-ins, failed attempts, MFA challenges, issued and revoked tokens, sign-outs and admin actions are stored in SQLite and written as one JSON line each (stdout by default, or a file), ready for CloudWatch, Datadog or Loki. Passwords, codes and tokens are never written. Rows older than `auditRetentionDays` (default 400) are deleted.

## Quick start

Requires Node.js 24 or later.

```sh
npm ci --ignore-scripts
npm run build
cp mamori.config.example.json mamori.config.json   # set issuer and clients
echo 'a-long-password' | npm run admin -- user add alice@example.co.jp "Alice"
npm run admin -- totp enroll alice@example.co.jp     # prints an otpauth:// URI to scan
npm run admin -- group add engineering && npm run admin -- group add-member engineering alice@example.co.jp
npm start
```

Put mamori behind a reverse proxy that terminates TLS, and set `"trustProxy": true` so that it uses the `X-Forwarded-*` headers from that proxy. Leave it `false` (the default) when nothing in front of mamori sets them, otherwise clients can choose their own IP address. The discovery document is at `/.well-known/openid-configuration` and a health check at `/healthz`.

Back up `mamori.key` separately from the database: without it the TOTP secrets cannot be read, and with it next to a database copy they can. Set `"encryptionKeyFile"` to keep it somewhere else. Secrets stored as plain text by earlier versions are encrypted at the next start.

The audit log goes to stdout unless `"auditLog"` is set to a file path or `"off"`.

## Development

```sh
npm run typecheck
npm test
```

The tests include an end-to-end run of the authorization code flow with [`openid-client`](https://github.com/panva/openid-client) against a real server.

## License

MIT
