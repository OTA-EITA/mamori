import { createVerify, generateKeyPairSync, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RetryLaterError } from '../src/provisioning/connector.js';
import { GoogleWorkspaceConnector } from '../src/provisioning/google.js';

// A fake Google: an OAuth token endpoint that checks the service account's
// signed JWT, and the Directory API users endpoints.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KEY = { client_email: 'mamori@project.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string };
const ADMIN = 'admin@example.co.jp';
const ACCESS = 'ya29.test-access-token';
const accounts = new Map<string, { id: string; primaryEmail: string; name: { givenName: string; familyName: string }; suspended: boolean; password?: string }>();
const requests: { method: string; path: string; body: unknown }[] = [];
let tokenRequests = 0;
let quotaNext = false;
let server: Server;
let origin: string;

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString();
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    const json = (status: number, b?: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(b === undefined ? '' : JSON.stringify(b));
    };
    const raw = await readBody(req);
    if (req.url === '/token') {
      tokenRequests++;
      const form = new URLSearchParams(raw);
      const [h, c, s] = (form.get('assertion') ?? '').split('.');
      const ok = createVerify('RSA-SHA256').update(`${h}.${c}`).verify(publicKey, Buffer.from(s ?? '', 'base64url'));
      const claims = JSON.parse(Buffer.from(c ?? '', 'base64url').toString()) as Record<string, unknown>;
      if (form.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer' || !ok) return json(400, { error: 'invalid_grant' });
      if (claims.iss !== KEY.client_email || claims.sub !== ADMIN || claims.aud !== `${origin}/token` || claims.scope !== 'https://www.googleapis.com/auth/admin.directory.user') {
        return json(400, { error: 'invalid_grant', error_description: 'bad claims' });
      }
      return json(200, { access_token: ACCESS, expires_in: 3600, token_type: 'Bearer' });
    }
    const body = raw ? JSON.parse(raw) : undefined;
    const path = new URL(req.url!, 'http://x').pathname.replace('/admin/directory/v1', '');
    requests.push({ method: req.method!, path, body });
    if (req.headers.authorization !== `Bearer ${ACCESS}`) return json(401, { error: { code: 401, message: 'Invalid Credentials' } });
    if (quotaNext) {
      quotaNext = false;
      return json(403, { error: { code: 403, message: 'Quota exceeded', errors: [{ reason: 'userRateLimitExceeded' }] } });
    }
    const key = decodeURIComponent(path.split('/')[2] ?? '');
    const found = [...accounts.values()].find((a) => a.id === key || a.primaryEmail.toLowerCase() === key.toLowerCase());
    if (req.method === 'POST' && path === '/users') {
      const a = { id: randomUUID().replace(/-/g, '').slice(0, 20), ...body, suspended: false };
      accounts.set(a.id, a);
      return json(200, { ...a, password: undefined });
    }
    if (!found) return json(404, { error: { code: 404, message: 'Resource Not Found: userKey' } });
    if (req.method === 'GET') return json(200, { ...found, password: undefined });
    if (req.method === 'PUT') {
      Object.assign(found, body);
      return json(200, { ...found, password: undefined });
    }
    return json(405);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  accounts.clear();
  requests.length = 0;
  tokenRequests = 0;
});

const google = (adminEmail = ADMIN) => new GoogleWorkspaceConnector('google-workspace', 'google-users', { ...KEY, token_uri: `${origin}/token` }, adminEmail, `${origin}/admin/directory/v1`);

describe('GoogleWorkspaceConnector', () => {
  it('creates a user with a random password and finds it by email', async () => {
    const g = google();
    const created = await g.create({ email: 'taro@example.co.jp', name: 'Taro Yamada' });
    expect(created).toMatchObject({ email: 'taro@example.co.jp', name: 'Taro Yamada', active: true });
    const sent = requests.find((r) => r.method === 'POST')!.body as { password: string; changePasswordAtNextLogin: boolean; name: unknown };
    expect(sent.password).toMatch(/^[\w-]{32}$/);
    expect(sent.changePasswordAtNextLogin).toBe(true);
    expect(sent.name).toEqual({ givenName: 'Taro', familyName: 'Yamada' });
    expect((await g.findByEmail('TARO@example.co.jp'))?.id).toBe(created.id);
    expect(await g.findByEmail('nobody@example.co.jp')).toBeUndefined();
  });

  it('suspends and reactivates, and never deletes', async () => {
    const g = google();
    const { id } = await g.create({ email: 'leaver@example.co.jp', name: 'Leaver' });
    await g.suspend(id);
    expect((await g.get(id))!.active).toBe(false);
    await g.reactivate(id);
    expect((await g.get(id))!.active).toBe(true);
    expect(requests.some((r) => r.method === 'DELETE')).toBe(false);
    // A one-word name fills both fields, which Google requires.
    expect(accounts.get(id)!.name).toEqual({ givenName: 'Leaver', familyName: 'Leaver' });
  });

  it('reuses the access token until it expires', async () => {
    const g = google();
    await g.findByEmail('a@example.co.jp');
    await g.findByEmail('b@example.co.jp');
    expect(tokenRequests).toBe(1);
  });

  it('retries quota errors later and explains token failures', async () => {
    quotaNext = true;
    await expect(google().findByEmail('a@example.co.jp')).rejects.toBeInstanceOf(RetryLaterError);
    const err = await google('someone-else@example.co.jp').findByEmail('a@example.co.jp').catch((e: Error) => e);
    expect((err as Error).message).toMatch(/Google token request failed: 400 invalid_grant/);
    expect((err as Error).message).not.toContain('PRIVATE KEY');
  });
});
