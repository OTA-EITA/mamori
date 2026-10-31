# mamori

A small, self-hosted identity provider for teams of 10 to 100 people: OpenID Connect single sign-on, TOTP and passkeys, and (planned) SCIM and provisioning connectors for the SaaS tools Japanese companies use.

mamori runs as one Node.js process with one SQLite file. It builds on the OpenID Certified [`oidc-provider`](https://github.com/panva/node-oidc-provider) library rather than implementing the protocol itself.

**Status: early development.** Not ready for production use.

See [docs/design.md](docs/design.md) for the scope and roadmap.

## License

MIT
