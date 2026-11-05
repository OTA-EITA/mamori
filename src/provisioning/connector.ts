// A SaaS that mamori provisions accounts in (docs/v0.3.md, "Outbound
// provisioning"). Connectors only talk to the SaaS; deciding what should
// happen is the engine's job.

export interface ExternalAccount {
  id: string;
  email: string;
  name: string;
  active: boolean;
}

export interface Person {
  email: string;
  name: string;
}

export interface Connector {
  // Unique per connector in the config, e.g. "slack" or "google-workspace".
  readonly name: string;
  // Active members of this mamori group get an account.
  readonly group: string;
  findByEmail(email: string): Promise<ExternalAccount | undefined>;
  get(id: string): Promise<ExternalAccount | undefined>;
  create(person: Person): Promise<ExternalAccount>;
  update(id: string, person: Person): Promise<void>;
  // Suspend or deactivate; never delete (docs/v0.3.md explains why).
  suspend(id: string): Promise<void>;
  reactivate(id: string): Promise<void>;
}

// Thrown by a connector when the SaaS asks to slow down (HTTP 429).
export class RetryLaterError extends Error {
  constructor(
    readonly seconds: number,
    message = `rate limited, retry in ${seconds}s`,
  ) {
    super(message);
  }
}
