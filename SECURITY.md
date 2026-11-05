# Security policy

mamori signs people in to their company's apps, so security reports are the most important kind of report it gets.

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/OTA-EITA/mamori/security/advisories/new), not in a public issue or pull request. Please include:

- the version or commit
- what an attacker can do, and what they need first (for example, a valid account, or network access to mamori)
- steps or a request that shows it

You will get an answer within a week. Once a fix is released, the advisory is published with credit to you, unless you prefer not to be named.

## Supported versions

Until 1.0, only the latest release gets security fixes.

## In scope

- Sign-in, MFA (TOTP, passkeys, recovery codes) and session handling
- The OpenID Connect provider configuration, tokens and the `amr` claim
- The account page and admin console: CSRF, access control, setup links
- SCIM: authentication, and changes it should not be able to make
- Secrets at rest: TOTP secrets, recovery codes, setup links, session ids, SCIM tokens
- The audit log leaking passwords, codes or tokens
- Provisioning connectors leaking credentials or acting on the wrong account

Bugs in `oidc-provider` itself belong to [that project](https://github.com/panva/node-oidc-provider/security), but tell us too if mamori's configuration makes them reachable.

## How mamori is built to be safe

The design documents explain the choices and their limits: [docs/design.md](docs/design.md), [docs/v0.2.md](docs/v0.2.md), [docs/v0.3.md](docs/v0.3.md). In short: PKCE for every app by default; secrets the server must read back are encrypted with a key kept outside the database, and everything else is stored as a hash; sign-in is throttled per email and IP without locking accounts; admin pages need a second factor; dependencies are installed only after they have been public for seven days, without install scripts.
