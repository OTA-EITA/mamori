import { readFileSync } from 'node:fs';
import type { ClientMetadata } from 'oidc-provider';

export interface MamoriConfig {
  // Public URL of this server, e.g. https://id.example.co.jp
  issuer: string;
  port: number;
  database: string;
  // Name shown in authenticator apps next to the account.
  totpIssuer: string;
  clients: ClientMetadata[];
}

export function loadConfig(path: string): MamoriConfig {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<MamoriConfig>;
  if (!raw.issuer) throw new Error(`${path}: "issuer" is required`);
  return {
    issuer: raw.issuer,
    port: raw.port ?? 3000,
    database: raw.database ?? 'mamori.db',
    totpIssuer: raw.totpIssuer ?? new URL(raw.issuer).hostname,
    clients: raw.clients ?? [],
  };
}
