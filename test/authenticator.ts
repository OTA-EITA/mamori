import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

// A software WebAuthn authenticator for tests: it holds one P-256 key pair and
// builds registration and authentication responses the way a browser and a
// platform authenticator would, so the server's real verification runs.

// Just enough CBOR (RFC 8949) for COSE keys and attestation objects.
function cbor(value: unknown): Buffer {
  const head = (major: number, n: number): Buffer => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  };
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  if (value instanceof Map) {
    const parts = [head(5, value.size)];
    for (const [k, v] of value) parts.push(cbor(k), cbor(v));
    return Buffer.concat(parts);
  }
  throw new Error(`cbor: unsupported ${typeof value}`);
}

const b64url = (b: Buffer | Uint8Array) => Buffer.from(b).toString('base64url');
const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest();

// authenticatorData flags (WebAuthn §6.1)
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;

export class SoftAuthenticator {
  readonly credentialId = randomBytes(16);
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  counter = 0;
  userHandle?: string;

  // synced: behave like iCloud Keychain / Google Password Manager (backed up).
  constructor(
    private readonly origin: string,
    private readonly synced = false,
  ) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  get id(): string {
    return b64url(this.credentialId);
  }

  private flags(extra: number): number {
    return UP | UV | extra | (this.synced ? BE | BS : 0);
  }

  private authData(rpId: string, flags: number, attested?: Buffer): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    return Buffer.concat([sha256(rpId), Buffer.from([flags]), counter, ...(attested ? [attested] : [])]);
  }

  // `options` is what the server's registration options endpoint returned.
  register(options: { challenge: string; rp: { id?: string }; user: { id: string } }) {
    const rpId = options.rp.id ?? new URL(this.origin).hostname;
    this.userHandle = options.user.id;
    const jwk = this.publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    const coseKey = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLength, this.credentialId, coseKey]);
    const authData = this.authData(rpId, this.flags(AT), attested);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const attestationObject = cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject), transports: ['internal'] },
    };
  }

  // `options` is what the server's authentication options endpoint returned.
  authenticate(options: { challenge: string; rpId?: string }, opts: { counter?: number } = {}) {
    const rpId = options.rpId ?? new URL(this.origin).hostname;
    this.counter = opts.counter ?? this.counter + 1;
    const authData = this.authData(rpId, this.flags(0));
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature), ...(this.userHandle ? { userHandle: this.userHandle } : {}) },
    };
  }
}
