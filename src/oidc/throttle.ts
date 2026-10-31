// Sign-in throttling (docs/v0.2.md, "Sign-in throttling").
//
// - Per email and IP: after LOCK_AFTER failures within WINDOW, that IP is
//   refused for that email until the window passes.
// - Per email from any IP: every failure after DELAY_AFTER adds a delay before
//   the answer, doubling up to MAX_DELAY. The account itself is never locked,
//   so a stranger who knows the address cannot keep the owner out.

const WINDOW_SECONDS = 15 * 60;
const LOCK_AFTER = 10;
const DELAY_AFTER = 5;
const MAX_DELAY_SECONDS = 30;

interface Counter {
  count: number;
  resetAt: number;
}

export class SignInThrottle {
  private readonly byEmailAndIp = new Map<string, Counter>();
  private readonly byEmail = new Map<string, Counter>();

  constructor(private readonly now: () => number) {}

  isLocked(email: string, ip: string): boolean {
    const c = this.live(this.byEmailAndIp, `${email}\n${ip}`);
    return c !== undefined && c.count >= LOCK_AFTER;
  }

  // Seconds to wait before answering a sign-in attempt for this email.
  delaySeconds(email: string): number {
    const c = this.live(this.byEmail, email);
    if (!c || c.count <= DELAY_AFTER) return 0;
    return Math.min(2 ** (c.count - DELAY_AFTER - 1), MAX_DELAY_SECONDS);
  }

  fail(email: string, ip: string): void {
    this.bump(this.byEmailAndIp, `${email}\n${ip}`);
    this.bump(this.byEmail, email);
  }

  succeed(email: string, ip: string): void {
    this.byEmailAndIp.delete(`${email}\n${ip}`);
    this.byEmail.delete(email);
  }

  private live(map: Map<string, Counter>, key: string): Counter | undefined {
    const c = map.get(key);
    if (c && c.resetAt <= this.now()) {
      map.delete(key);
      return undefined;
    }
    return c;
  }

  private bump(map: Map<string, Counter>, key: string): void {
    const c = this.live(map, key);
    map.set(key, { count: (c?.count ?? 0) + 1, resetAt: c?.resetAt ?? this.now() + WINDOW_SECONDS });
  }
}
