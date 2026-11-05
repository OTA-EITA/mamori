import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { connectorsFromConfig } from './fromConfig.js';

const dir = mkdtempSync(join(tmpdir(), 'mamori-conn-'));
const tokenFile = join(dir, 'slack-token');
writeFileSync(tokenFile, 'xoxp-test\n');
const keyFile = join(dir, 'sa.json');
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
writeFileSync(keyFile, JSON.stringify({ client_email: 'sa@p.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }));
const notAKey = join(dir, 'other.json');
writeFileSync(notAKey, '{}');

describe('connectorsFromConfig', () => {
  it('builds connectors named after their type unless named', () => {
    const list = connectorsFromConfig([
      { type: 'slack', group: 'slack-users', tokenFile },
      { type: 'google-workspace', name: 'google', group: 'google-users', serviceAccountKeyFile: keyFile, adminEmail: 'admin@example.co.jp' },
    ]);
    expect(list.map((c) => [c.name, c.group])).toEqual([
      ['slack', 'slack-users'],
      ['google', 'google-users'],
    ]);
    expect(connectorsFromConfig(undefined)).toEqual([]);
  });

  it('refuses unclear or broken configs', () => {
    expect(() => connectorsFromConfig([{ type: 'slack', group: 'a', tokenFile }, { type: 'slack', group: 'b', tokenFile }])).toThrow(/named slack/);
    expect(() => connectorsFromConfig([{ type: 'slack', group: '', tokenFile }])).toThrow(/group/);
    expect(() => connectorsFromConfig([{ type: 'google-workspace', group: 'g', serviceAccountKeyFile: notAKey, adminEmail: 'a@b.c' }])).toThrow(/not a service account key/);
    expect(() => connectorsFromConfig([{ type: 'slack', group: 'g', tokenFile: join(dir, 'missing') }])).toThrow();
  });
});
