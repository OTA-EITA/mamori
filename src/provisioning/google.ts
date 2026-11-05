import { createSign, randomBytes } from 'node:crypto';
import { RetryLaterError, type Connector, type ExternalAccount, type Person } from './connector.js';

// Google Workspace through the Admin SDK Directory API (docs/v0.3.md, "Google
// Workspace"). A service account with domain-wide delegation acts as an admin;
// mamori signs the service account's JWT itself, so there is no Google client
// library. Leavers are suspended, never deleted.

const SCOPE = 'https://www.googleapis.com/auth/admin.directory.user';

export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

interface GoogleUser {
  id: string;
  primaryEmail: string;
  name?: { givenName?: string; familyName?: string; fullName?: string };
  suspended?: boolean;
}

// Google needs both a given name and a family name. mamori keeps one name: the
// first word goes to givenName and the rest to familyName (or the same word
// again for a one-word name).
function nameParts(name: string): { givenName: string; familyName: string } {
  const [given, ...rest] = name.trim().split(/\s+/);
  const g = given || name;
  return { givenName: g, familyName: rest.join(' ') || g };
}

const b64url = (v: string | Buffer) => Buffer.from(v).toString('base64url');

export class GoogleWorkspaceConnector implements Connector {
  private token?: { value: string; expires: number };

  constructor(
    readonly name: string,
    readonly group: string,
    private readonly key: ServiceAccountKey,
    // The Workspace admin the service account acts as (domain-wide delegation).
    private readonly adminEmail: string,
    private readonly baseUrl = 'https://admin.googleapis.com/admin/directory/v1',
    private readonly fetchImpl: typeof fetch = fetch,
    private readonly now: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  // OAuth 2.0 JWT bearer grant (RFC 7523) with a service account key.
  private async accessToken(): Promise<string> {
    if (this.token && this.token.expires > this.now() + 60) return this.token.value;
    const iat = this.now();
    const tokenUri = this.key.token_uri ?? 'https://oauth2.googleapis.com/token';
    const unsigned = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${b64url(
      JSON.stringify({ iss: this.key.client_email, sub: this.adminEmail, scope: SCOPE, aud: tokenUri, iat, exp: iat + 3600 }),
    )}`;
    const signature = createSign('RSA-SHA256').update(unsigned).sign(this.key.private_key);
    const res = await this.fetchImpl(tokenUri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${b64url(signature)}` }).toString(),
      signal: AbortSignal.timeout(20_000),
    });
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !json.access_token) throw new Error(`Google token request failed: ${res.status} ${json.error ?? ''} ${json.error_description ?? ''}`.trim());
    this.token = { value: json.access_token, expires: iat + (json.expires_in ?? 3600) };
    return this.token.value;
  }

  private async call(method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
    const res = await this.fetchImpl(this.baseUrl + path, {
      method,
      headers: { authorization: `Bearer ${await this.accessToken()}`, ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(20_000),
    });
    const text = await res.text();
    const json = text ? (JSON.parse(text) as unknown) : undefined;
    const reason = (json as { error?: { errors?: { reason?: string }[]; message?: string } } | undefined)?.error;
    // Google answers quota problems with 429, or 403 and a rateLimitExceeded reason.
    if (res.status === 429 || (res.status === 403 && reason?.errors?.some((e) => /rateLimitExceeded|userRateLimitExceeded/.test(e.reason ?? '')))) {
      throw new RetryLaterError(Number(res.headers.get('retry-after')) || 30, `Google rate limit (${res.status})`);
    }
    if (res.status >= 400 && res.status !== 404) throw new Error(`Google ${method} ${path} failed: ${res.status} ${reason?.message ?? ''}`.trim());
    return { status: res.status, json };
  }

  private toAccount(u: GoogleUser): ExternalAccount {
    const name = u.name?.fullName ?? [u.name?.givenName, u.name?.familyName].filter(Boolean).join(' ');
    return { id: u.id, email: u.primaryEmail, name, active: u.suspended !== true };
  }

  // users.get accepts the primary email or the user id as the key.
  async findByEmail(email: string): Promise<ExternalAccount | undefined> {
    return this.get(email);
  }

  async get(idOrEmail: string): Promise<ExternalAccount | undefined> {
    const { status, json } = await this.call('GET', `/users/${encodeURIComponent(idOrEmail)}`);
    return status === 404 || !json ? undefined : this.toAccount(json as GoogleUser);
  }

  async create(person: Person): Promise<ExternalAccount> {
    // Google requires a password. It is random and never stored or shown; the
    // person sets their own with Google's password reset (docs/v0.3.md).
    const { json } = await this.call('POST', '/users', {
      primaryEmail: person.email,
      name: nameParts(person.name),
      password: randomBytes(24).toString('base64url'),
      changePasswordAtNextLogin: true,
    });
    return this.toAccount(json as GoogleUser);
  }

  async update(id: string, person: Person): Promise<void> {
    await this.call('PUT', `/users/${encodeURIComponent(id)}`, { primaryEmail: person.email, name: nameParts(person.name) });
  }

  async suspend(id: string): Promise<void> {
    await this.call('PUT', `/users/${encodeURIComponent(id)}`, { suspended: true });
  }

  async reactivate(id: string): Promise<void> {
    await this.call('PUT', `/users/${encodeURIComponent(id)}`, { suspended: false });
  }
}
