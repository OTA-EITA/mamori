import { readFileSync } from 'node:fs';
import type { Connector } from './connector.js';
import { GoogleWorkspaceConnector, type ServiceAccountKey } from './google.js';
import { SlackConnector } from './slack.js';

// Connectors from the config file. Credentials are read from files named in
// the config, never from the database (docs/v0.3.md).
export type ConnectorConfig =
  | { type: 'slack'; name?: string; group: string; tokenFile: string; baseUrl?: string }
  | { type: 'google-workspace'; name?: string; group: string; serviceAccountKeyFile: string; adminEmail: string; baseUrl?: string };

export function connectorsFromConfig(list: ConnectorConfig[] = []): Connector[] {
  const names = new Set<string>();
  return list.map((c) => {
    const name = c.name ?? c.type;
    if (names.has(name)) throw new Error(`two connectors are named ${name}; give one a "name"`);
    names.add(name);
    if (!c.group) throw new Error(`connector ${name}: "group" is required`);
    if (c.type === 'slack') {
      const token = readFileSync(c.tokenFile, 'utf8').trim();
      return new SlackConnector(name, c.group, token, c.baseUrl);
    }
    if (c.type === 'google-workspace') {
      const key = JSON.parse(readFileSync(c.serviceAccountKeyFile, 'utf8')) as ServiceAccountKey;
      if (!key.client_email || !key.private_key) throw new Error(`connector ${name}: ${c.serviceAccountKeyFile} is not a service account key`);
      if (!c.adminEmail) throw new Error(`connector ${name}: "adminEmail" is required`);
      return new GoogleWorkspaceConnector(name, c.group, key, c.adminEmail, c.baseUrl);
    }
    throw new Error(`unknown connector type ${(c as { type: string }).type}`);
  });
}
