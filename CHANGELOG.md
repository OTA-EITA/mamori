# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version can change the config or the database.

## Unreleased

## 0.3.0

Joining and leaving the company is one change in mamori.

- SCIM 2.0 server at `/scim/v2` for an HR system or another IdP (Microsoft Entra ID, Okta) to manage users and groups.
- Outbound provisioning to Google Workspace and Slack. Each connector follows one mamori group; leavers are suspended, never deleted. Changes are queued and retried for up to a day, and `mamori-admin provision reconcile` finds changes made by hand.
- Sign in to Google Workspace with mamori through Google's custom OIDC SSO profile ([docs/google-sso.md](docs/google-sso.md)).
- `pkce_optional` for confidential clients that cannot send PKCE.

## 0.2.0

Running mamori day to day.

- Passkeys for sign-in and as a second factor.
- Account page: set up TOTP, recovery codes, passkeys.
- MFA policy: `"mfa": "required"` sends users without a second factor through setup during sign-in.
- Admin console: users, setup links instead of passwords, disable and enable, reset second factors, groups, audit log.
- Groups and the `groups` claim.
- Audit log in SQLite and as JSON lines.
- TOTP secrets encrypted at rest with a key outside the database.
- Sign-in throttling per email and IP, without locking accounts.
- `amr` includes `mfa` when two factors were used. Apps that compared the whole array should check for `mfa`.

## 0.1.0

- OpenID Connect provider (authorization code + PKCE), email and password sign-in with TOTP, clients from the config file, CLI to add users.
