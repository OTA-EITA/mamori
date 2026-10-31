# Design

## Who it is for

Teams of 10 to 100 people that want single sign-on and MFA for their SaaS tools but cannot justify a per-user IdP subscription. Typical example: a small company in Japan that uses Google Workspace, Slack, HRMOS, freee or Money Forward, and has one person who looks after IT part-time.

## Goals

- One Node.js process and one SQLite file. No Redis, no separate database server.
- Standard protocols first: OpenID Connect (authorization code with PKCE), then SCIM 2.0 and SAML 2.0.
- MFA that people actually use: TOTP from day one, passkeys (WebAuthn) next.
- An audit log that an SRE can ship somewhere else (JSON lines).
- Provisioning connectors for the SaaS tools Japanese companies use, so that joining and leaving the company is one change in mamori.

## Non-goals

- Replacing Keycloak, Authentik or Zitadel for large organisations.
- Being a customer identity (CIAM) platform with social login and self sign-up.
- Horizontal scaling. One instance with backups is the target.

## Building blocks

| Part | Choice | Why |
|---|---|---|
| OpenID Provider | [`oidc-provider`](https://github.com/panva/node-oidc-provider) | OpenID Certified, widely used, so mamori does not implement the protocol itself |
| Storage | `node:sqlite` | Built into Node 24, no native add-on to compile |
| Passwords | `node:crypto` scrypt | No extra dependency |
| TOTP | own implementation (RFC 6238), tested against the RFC test vectors | Small, and easy to audit |

## Roadmap

- **v0.1**: OIDC provider with authorization code + PKCE, users with password + TOTP, clients from a config file, CLI to add users and clients
- **v0.2**: passkeys, groups, audit log, minimal admin UI
- **v0.3**: SCIM 2.0 server, first connectors (Google Workspace, Slack)
- **v0.4**: SAML 2.0, HRMOS / freee / Money Forward connectors
