import { randomInt } from 'node:crypto';
import { RetryLaterError, type Connector, type ExternalAccount, type Person } from './connector.js';

// Slack through its SCIM 2.0 API (docs/v0.3.md, "Slack"). Only on Business+ and
// Enterprise plans. DELETE deactivates a user (Slack never deletes users), and
// PATCH active=true brings them back.

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

interface SlackUser {
  id: string;
  userName?: string;
  displayName?: string;
  name?: { givenName?: string; familyName?: string };
  emails?: { value: string; primary?: boolean }[];
  active?: boolean;
}

// Slack user names: lower case, at most 21 characters, letters, digits, ".",
// "_" and "-" (anything else becomes "_" at Slack). Made from the email's
// local part so it is recognisable.
export function slackUserName(email: string, suffix = ''): string {
  const base = email.split('@')[0]!.toLowerCase().replace(/[^a-z0-9._-]/g, '_').replace(/^[._-]+/, '') || 'user';
  return base.slice(0, 21 - suffix.length) + suffix;
}

// Slack shows givenName + familyName as the full name. mamori keeps one name,
// so the first word goes to givenName and the rest to familyName.
function nameParts(name: string): { givenName: string; familyName: string } {
  const [given, ...rest] = name.trim().split(/\s+/);
  return { givenName: given ?? name, familyName: rest.join(' ') };
}

export class SlackConnector implements Connector {
  constructor(
    readonly name: string,
    readonly group: string,
    private readonly token: string,
    private readonly baseUrl = 'https://api.slack.com/scim/v2',
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async call(method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }> {
    const res = await this.fetchImpl(this.baseUrl + path, {
      method,
      headers: { authorization: `Bearer ${this.token}`, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(20_000),
    });
    if (res.status === 429) throw new RetryLaterError(Number(res.headers.get('retry-after')) || 30, 'Slack rate limit (429)');
    const text = await res.text();
    const json = text ? (JSON.parse(text) as unknown) : undefined;
    if (res.status >= 400 && res.status !== 404) {
      const detail = (json as { Errors?: { description?: string }; detail?: string } | undefined)?.Errors?.description ?? (json as { detail?: string } | undefined)?.detail ?? '';
      const err = new Error(`Slack ${method} ${path.split('?')[0]} failed: ${res.status} ${detail}`.trim());
      (err as Error & { status?: number }).status = res.status;
      throw err;
    }
    return { status: res.status, json };
  }

  private toAccount(u: SlackUser): ExternalAccount {
    const email = (u.emails?.find((e) => e.primary) ?? u.emails?.[0])?.value ?? '';
    const full = [u.name?.givenName, u.name?.familyName].filter(Boolean).join(' ') || u.displayName || u.userName || '';
    return { id: u.id, email, name: full, active: u.active !== false };
  }

  async findByEmail(email: string): Promise<ExternalAccount | undefined> {
    const { json } = await this.call('GET', `/Users?filter=${encodeURIComponent(`email eq "${email}"`)}`);
    const first = (json as { Resources?: SlackUser[] } | undefined)?.Resources?.[0];
    return first ? this.toAccount(first) : undefined;
  }

  async get(id: string): Promise<ExternalAccount | undefined> {
    const { status, json } = await this.call('GET', `/Users/${encodeURIComponent(id)}`);
    return status === 404 || !json ? undefined : this.toAccount(json as SlackUser);
  }

  async create(person: Person): Promise<ExternalAccount> {
    // Slack user names must be unique (also against channel names); retry with
    // a short number at the end when one is taken.
    for (let attempt = 0; ; attempt++) {
      const suffix = attempt === 0 ? '' : String(randomInt(100, 1000));
      try {
        const { json } = await this.call('POST', '/Users', {
          schemas: [USER_SCHEMA],
          userName: slackUserName(person.email, suffix),
          name: nameParts(person.name),
          emails: [{ value: person.email, type: 'work', primary: true }],
          active: true,
        });
        return this.toAccount(json as SlackUser);
      } catch (err) {
        const status = (err as { status?: number }).status;
        if (status === 409 && attempt < 3 && /user ?name|username/i.test((err as Error).message)) continue;
        throw err;
      }
    }
  }

  async update(id: string, person: Person): Promise<void> {
    const { givenName, familyName } = nameParts(person.name);
    await this.call('PATCH', `/Users/${encodeURIComponent(id)}`, {
      schemas: [PATCH_SCHEMA],
      Operations: [
        { op: 'replace', path: 'name.givenName', value: givenName },
        { op: 'replace', path: 'name.familyName', value: familyName },
        { op: 'replace', path: 'emails', value: [{ value: person.email, type: 'work', primary: true }] },
      ],
    });
  }

  async suspend(id: string): Promise<void> {
    await this.call('DELETE', `/Users/${encodeURIComponent(id)}`);
  }

  async reactivate(id: string): Promise<void> {
    await this.call('PATCH', `/Users/${encodeURIComponent(id)}`, { schemas: [PATCH_SCHEMA], Operations: [{ op: 'replace', path: 'active', value: true }] });
  }
}
