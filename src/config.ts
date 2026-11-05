import { readFileSync } from 'node:fs';
import type { ClientMetadata } from 'oidc-provider';

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
    auditLog: raw.auditLog ?? '-',
    auditRetentionDays: raw.auditRetentionDays ?? 400,
  };
}
