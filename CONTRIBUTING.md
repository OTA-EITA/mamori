# Contributing

Thank you for helping. mamori is small on purpose: one Node.js process, one SQLite file, few dependencies. Changes that keep it that way are the easiest to accept.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach. The design documents in [docs/](docs/) say what is in and out of scope.
- Security problems go through [SECURITY.md](SECURITY.md), not issues.

## Setting up

Requires Node.js 24 or later.

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
```

The tests start real servers on random local ports. They never call Google, Slack or any other service: the connectors are tested against fake servers in `test/`, and passkeys against a software authenticator (`test/authenticator.ts`).

## What a pull request needs

- Tests for the change, including the failure cases. For a bug fix, a test that fails without the fix.
- `npm run typecheck` and `npm test` passing.
- No new dependency unless it is clearly worth it. New dependencies must have been published at least seven days ago (`.npmrc` enforces this) and must not need install scripts.
- User-visible changes noted in [CHANGELOG.md](CHANGELOG.md) under "Unreleased".
- Short commit subjects in English, in the imperative ("Add …", "Fix …").

## Code style

TypeScript in strict mode, ES modules, no framework. Comments say why, not what. Never write passwords, codes, tokens or secrets to logs or the audit log.
