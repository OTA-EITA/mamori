import type { DatabaseSync } from 'node:sqlite';
import Provider, { type Configuration } from 'oidc-provider';
import type { MamoriConfig } from '../config.js';
import { SqliteAdapter } from '../store/oidcAdapter.js';
import type { UserStore } from '../store/users.js';
import { cookieKeys, signingJwks } from './keys.js';

export function createProvider(config: MamoriConfig, db: DatabaseSync, users: UserStore): Provider {
  const configuration: Configuration = {
    adapter: (name: string) => new SqliteAdapter(db, name),
    clients: config.clients,
    jwks: signingJwks(db) as Configuration['jwks'],
    cookies: { keys: cookieKeys(db) },
    // Require PKCE for every client, not only public ones.
    pkce: { required: () => true },
    scopes: ['openid', 'email', 'profile', 'offline_access'],
    claims: { openid: ['sub', 'amr'], email: ['email', 'email_verified'], profile: ['name'] },
    // Many SaaS apps read the email from the ID token instead of calling
    // userinfo, so put the claims of the granted scopes in the ID token too.
    conformIdTokenClaims: false,
    features: { devInteractions: { enabled: false }, revocation: { enabled: true } },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    ttl: { AccessToken: 60 * 10, AuthorizationCode: 60, IdToken: 60 * 10, Interaction: 60 * 10, Session: 60 * 60 * 12 },
    async findAccount(_ctx, id) {
      const user = users.findById(id);
      if (!user || user.disabled) return undefined;
      return {
        accountId: user.id,
        async claims() {
          return { sub: user.id, email: user.email, email_verified: true, name: user.name };
        },
      };
    },
  };
  const provider = new Provider(config.issuer, configuration);
  // Behind a reverse proxy that terminates TLS.
  provider.proxy = true;
  return provider;
}
