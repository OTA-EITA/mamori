import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RetryLaterError } from '../src/provisioning/connector.js';
import { slackUserName, SlackConnector } from '../src/provisioning/slack.js';

// A fake Slack SCIM v2 API that keeps users in memory and records requests.
const TOKEN = 'xoxp-test-token';
const users = new Map<string, { id: string; userName: string; name: { givenName: string; familyName: string }; emails: { value: string; primary: boolean }[]; active: boolean }>();
const requests: { method: string; url: string; body: unknown }[] = [];
let rateLimitNext = 0;
let server: Server;
let base: string;

async function body(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString();
  return text ? JSON.parse(text) : undefined;
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    const json = (status: number, b?: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(b === undefined ? undefined : JSON.stringify(b));
    };
    const b = await body(req);
    requests.push({ method: req.method!, url: req.url!, body: b });
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, { Errors: { description: 'invalid_authentication', code: 401 } });
    if (rateLimitNext > 0) {
      rateLimitNext--;
      res.writeHead(429, { 'retry-after': '7' });
      return res.end();
    }
    const url = new URL(req.url!, 'http://x');
    const id = /^\/scim\/v2\/Users\/([^/]+)$/.exec(url.pathname)?.[1];
    if (req.method === 'GET' && url.pathname === '/scim/v2/Users') {
      const email = /email eq "([^"]+)"/i.exec(url.searchParams.get('filter') ?? '')?.[1];
      const found = [...users.values()].filter((u) => u.emails.some((e) => e.value.toLowerCase() === email?.toLowerCase()));
      return json(200, { totalResults: found.length, Resources: found });
    }
    if (req.method === 'POST' && url.pathname === '/scim/v2/Users') {
      const input = b as { userName: string; name: { givenName: string; familyName: string }; emails: { value: string; primary: boolean }[] };
      if ([...users.values()].some((u) => u.userName === input.userName)) return json(409, { Errors: { description: 'username_taken', code: 409 } });
      const u = { id: `U${randomUUID().slice(0, 8)}`, userName: input.userName, name: input.name, emails: input.emails, active: true };
      users.set(u.id, u);
      return json(201, u);
    }
    const u = id ? users.get(id) : undefined;
    if (!u) return json(404, { Errors: { description: 'user_not_found', code: 404 } });
    if (req.method === 'GET') return json(200, u);
    if (req.method === 'DELETE') {
      u.active = false;
      return json(204);
    }
    if (req.method === 'PATCH') {
      for (const op of (b as { Operations: { path: string; value: unknown }[] }).Operations) {
        if (op.path === 'active') u.active = op.value as boolean;
        if (op.path === 'name.givenName') u.name.givenName = op.value as string;
        if (op.path === 'name.familyName') u.name.familyName = op.value as string;
        if (op.path === 'emails') u.emails = op.value as typeof u.emails;
      }
      return json(200, u);
    }
    return json(405);
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/scim/v2`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  users.clear();
  requests.length = 0;
  rateLimitNext = 0;
});

const slack = (token = TOKEN) => new SlackConnector('slack', 'slack-users', token, base);

describe('slackUserName', () => {
  it('makes a valid Slack user name from an email address', () => {
    expect(slackUserName('Taro.Yamada@example.co.jp')).toBe('taro.yamada');
    expect(slackUserName('a+b@example.co.jp')).toBe('a_b');
    expect(slackUserName('a.very.long.local.part.name@example.co.jp')).toHaveLength(21);
    expect(slackUserName('a.very.long.local.part.name@example.co.jp', '123')).toMatch(/^.{18}123$/);
  });
});

describe('SlackConnector', () => {
  it('creates, finds, updates, deactivates and reactivates a user', async () => {
    const s = slack();
    const created = await s.create({ email: 'taro.yamada@example.co.jp', name: 'Taro Yamada' });
    expect(created).toMatchObject({ email: 'taro.yamada@example.co.jp', name: 'Taro Yamada', active: true });
    expect(requests.at(-1)!.body).toMatchObject({ userName: 'taro.yamada', name: { givenName: 'Taro', familyName: 'Yamada' } });
    expect((await s.findByEmail('TARO.YAMADA@example.co.jp'))?.id).toBe(created.id);
    expect(await s.findByEmail('nobody@example.co.jp')).toBeUndefined();

    await s.update(created.id, { email: 'taro.y@example.co.jp', name: 'Taro Suzuki' });
    expect(await s.get(created.id)).toMatchObject({ email: 'taro.y@example.co.jp', name: 'Taro Suzuki' });

    await s.suspend(created.id);
    expect(requests.at(-1)).toMatchObject({ method: 'DELETE', url: `/scim/v2/Users/${created.id}` });
    expect((await s.get(created.id))!.active).toBe(false);
    await s.reactivate(created.id);
    expect(requests.at(-1)!.body).toEqual({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: true }] });
    expect((await s.get(created.id))!.active).toBe(true);
    expect(await s.get('UNOPE')).toBeUndefined();
  });

  it('adds a number when the user name is taken', async () => {
    const s = slack();
    await s.create({ email: 'taro@a.example', name: 'Taro A' });
    const second = await s.create({ email: 'taro@b.example', name: 'Taro B' });
    expect(users.get(second.id)!.userName).toMatch(/^taro\d{3}$/);
  });

  it('turns 429 into a retry with the time Slack asks for', async () => {
    rateLimitNext = 1;
    await expect(slack().findByEmail('a@example.co.jp')).rejects.toEqual(new RetryLaterError(7, 'Slack rate limit (429)'));
  });

  it('reports errors without the token', async () => {
    const err = await slack('xoxp-wrong-token').findByEmail('a@example.co.jp').catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toContain('401');
    expect((err as Error).message).not.toContain('xoxp');
  });
});
