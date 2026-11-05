import type { EventEmitter } from 'node:events';
import type { DatabaseSync } from 'node:sqlite';
import Provider, { type Configuration } from 'oidc-provider';
import type { MamoriConfig } from '../config.js';
import { SqliteAdapter } from '../store/oidcAdapter.js';
import type { UserStore } from '../store/users.js';
import type { AuditLog } from '../audit/audit.js';
import type { GroupStore } from '../store/groups.js';
import { consoleClient } from '../console/console.js';
import { logoutConfirmPage } from '../console/pages.js';
import { cookieKeys, signingJwks } from './keys.js';

export function createProvider(config: MamoriConfig, db: DatabaseSync, users: UserStore, audit?: AuditLog, groups?: GroupStore): Provider {
  const configuration: Configuration = {
    adapter: (name: string) => new SqliteAdapter(db, name),
    clients: [...config.clients, consoleClient(config.issuer)],
    jwks: signingJwks(db) as Configuration['jwks'],
    cookies: { keys: cookieKeys(db) },
    // Require PKCE for every client, not only public ones. A confidential
    // client (one with a secret) can opt out with "pkce_optional": true, for
    // apps that do not send PKCE, such as some SaaS SSO settings. Public
    // clients cannot opt out.
    pkce: {
      required: (_ctx, client) => !(client.clientAuthMethod !== 'none' && (client as unknown as { pkce_optional?: boolean }).pkce_optional === true),
    },
    extraClientMetadata: {
      properties: ['pkce_optional'],
      validator(_ctx, key, value) {
        if (key === 'pkce_optional' && value !== undefined && typeof value !== 'boolean') throw new Error('pkce_optional must be true or false');
      },
    },
    scopes: ['openid', 'email', 'profile', 'groups', 'offline_access'],
    claims: { openid: ['sub', 'amr'], email: ['email', 'email_verified'], profile: ['name'], groups: ['groups'] },
    // Many SaaS apps read the email from the ID token instead of calling
    // userinfo, so put the claims of the granted scopes in the ID token too.
    conformIdTokenClaims: false,
    features: {
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource(ctx, form) {
          ctx.type = 'html';
          ctx.body = logoutConfirmPage(form);
        },
      },
    },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    ttl: { AccessToken: 60 * 10, AuthorizationCode: 60, IdToken: 60 * 10, Interaction: 60 * 10, Session: 60 * 60 * 12 },
    async findAccount(_ctx, id) {
      const user = users.findById(id);
      if (!user || user.disabled) return undefined;
      return {
        accountId: user.id,
        async claims() {
          return { sub: user.id, email: user.email, email_verified: true, name: user.name, groups: groups?.namesOf(user.id) ?? [] };
        },
      };
    },
  };
  const provider = new Provider(config.issuer, configuration);
  // Only believe X-Forwarded-* when the admin says there is a proxy in front.
  provider.proxy = config.trustProxy ?? false;
  if (audit) logTokenEvents(provider, audit);
  return provider;
}

interface IssuedToken {
  accountId?: string;
  clientId?: string;
  scope?: string;
}

interface EventContext {
  oidc?: { client?: { clientId?: string } };
}

// Token events for the audit log. Only who, which app and which scopes: an
// opaque access token's id is the token itself, so it is never written.
// Stored tokens (opaque access tokens, refresh tokens) emit "<kind>.saved";
// tokens that are not stored (JWT access tokens) emit "<kind>.issued". Each
// token emits only one of the two. Not every runtime event is in the type
// definitions, so the listeners go through EventEmitter.
function logTokenEvents(provider: Provider, audit: AuditLog): void {
  const events = provider as unknown as EventEmitter;
  const issued = (kind: 'access_token' | 'refresh_token') => (token: IssuedToken) => {
    audit.write({
      event: 'token.issued',
      token_type: kind,
      ...(token.accountId ? { actor: { type: 'user', id: token.accountId } } : {}),
      ...(token.clientId ? { client_id: token.clientId } : {}),
      ...(token.scope ? { scope: token.scope } : {}),
    });
  };
  events.on('access_token.saved', issued('access_token'));
  events.on('access_token.issued', issued('access_token'));
  events.on('refresh_token.saved', issued('refresh_token'));
  events.on('grant.revoked', (ctx: EventContext, grantId: string) => {
    const clientId = ctx.oidc?.client?.clientId;
    audit.write({ event: 'token.revoked', grant_id: grantId, ...(clientId ? { client_id: clientId } : {}) });
  });
  events.on('end_session.success', (ctx: EventContext) => {
    const clientId = ctx.oidc?.client?.clientId;
    audit.write({ event: 'sign_out', ...(clientId ? { client_id: clientId } : {}) });
  });
}
