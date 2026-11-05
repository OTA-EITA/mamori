import { readFileSync } from 'node:fs';
import type { ClientMetadata } from 'oidc-provider';
import type { ConnectorConfig } from './provisioning/fromConfig.js';

export interface MamoriConfig {
  // Public URL of this server, e.g. https://id.example.co.jp
  issuer: string;
  port: number;
  // Set to true only when mamori is behind a reverse proxy you run, which
  // overwrites or appends X-Forwarded-For / -Proto / -Host.
  trustProxy?: boolean;
  database: string;
  // Name shown in authenticator apps next to the account.
  totpIssuer: string;
  clients: ClientMetadata[];
  // Key that seals TOTP secrets in the database. Created on first start.
  // Keep it out of database backups, and back it up separately.
  encryptionKeyFile: string;
  // "required": every user must have a second factor, and one who has none
  // sets it up during sign-in. Unset means "required" for a new database and
  // "optional" for one upgraded from v0.1 (see resolveMfaPolicy).
  mfa?: 'optional' | 'required';
  // Outbound provisioning to Google Workspace and Slack (docs/v0.3.md).
  connectors?: ConnectorConfig[];
  // Audit log lines: "-" for stdout, "off", or a file path.
  auditLog: string;
  // Audit rows older than this are deleted by the hourly cleanup.
  auditRetentionDays: number;
}

export function loadConfig(path: string): MamoriConfig {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as Partial<MamoriConfig>;
  if (!raw.issuer) throw new Error(`${path}: "issuer" is required`);
  return {
    issuer: raw.issuer,
    port: raw.port ?? 3000,
    trustProxy: raw.trustProxy ?? false,
    database: raw.database ?? 'mamori.db',
    totpIssuer: raw.totpIssuer ?? new URL(raw.issuer).hostname,
    clients: raw.clients ?? [],
    encryptionKeyFile: raw.encryptionKeyFile ?? 'mamori.key',
    ...(raw.mfa ? { mfa: raw.mfa } : {}),
    ...(raw.connectors ? { connectors: raw.connectors } : {}),
    auditLog: raw.auditLog ?? '-',
    auditRetentionDays: raw.auditRetentionDays ?? 400,
  };
}

// The MFA policy when the config does not say. A database created by v0.2 or
// later uses "required"; one upgraded from v0.1 keeps working as before
// ("optional") so an upgrade does not suddenly send everyone through setup.
export function resolveMfaPolicy(config: Pick<MamoriConfig, 'mfa'>, createdBy: string | undefined): { policy: 'optional' | 'required'; warning?: string } {
  if (config.mfa) {
    if (config.mfa !== 'optional' && config.mfa !== 'required') throw new Error('"mfa" must be "optional" or "required"');
    return { policy: config.mfa };
  }
  if (createdBy === 'v0.1') {
    return { policy: 'optional', warning: 'mfa is not set in the config; using "optional" because this database came from v0.1. Set "mfa": "required" to require a second factor.' };
  }
  return { policy: 'required' };
}
