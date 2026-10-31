# mamori

A small, self-hosted identity provider for teams of 10 to 100 people: OpenID Connect single sign-on, TOTP and passkeys, and (planned) SCIM and provisioning connectors for the SaaS tools Japanese companies use.

mamori runs as one Node.js process with one SQLite file. It builds on the OpenID Certified [`oidc-provider`](https://github.com/panva/node-oidc-provider) library rather than implementing the protocol itself.

**Status: early development.** Not ready for production use.

See [docs/design.md](docs/design.md) for the scope and roadmap.

## What works today

- OpenID Connect provider with the authorization code flow. PKCE (S256) is required for every client.
- Sign-in with email and password, plus TOTP for users who have it set up. The ID token's `amr` says which (`["pwd"]` or `["pwd", "otp"]`).
- Accounts are locked for 15 minutes after 10 failed attempts. Disabled users cannot sign in.
- Passwords are hashed with scrypt. Signing keys and cookie keys are generated on first start and kept in the SQLite file.

## Quick start

Requires Node.js 24 or later.

```sh
npm ci --ignore-scripts
npm run build
cp mamori.config.example.json mamori.config.json   # set issuer and clients
echo 'a-long-password' | npm run admin -- user add alice@example.co.jp "Alice"
npm run admin -- totp enroll alice@example.co.jp     # prints an otpauth:// URI to scan
npm start
```

Put mamori behind a reverse proxy that terminates TLS; it trusts `X-Forwarded-*` headers. The discovery document is at `/.well-known/openid-configuration` and a health check at `/healthz`.

## Development

```sh
npm run typecheck
npm test
```

The tests include an end-to-end run of the authorization code flow with [`openid-client`](https://github.com/panva/openid-client) against a real server.

## License

MIT
