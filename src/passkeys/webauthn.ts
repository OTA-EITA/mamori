import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Passkey } from '../store/passkeys.js';

// WebAuthn settings for one issuer. The RP ID is the issuer's host name and the
// expected origin is the issuer's origin, so if the issuer moves to another
// host, existing passkeys stop working (docs/v0.2.md, "Passkeys").

export class WebAuthn {
  readonly rpID: string;
  readonly origin: string;

  constructor(
    issuer: string,
    private readonly rpName: string,
  ) {
    const url = new URL(issuer);
    this.rpID = url.hostname;
    this.origin = url.origin;
  }

  registrationOptions(user: { id: string; email: string; name: string }, existing: Passkey[]) {
    return generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpID,
      userName: user.email,
      userDisplayName: user.name,
      userID: new TextEncoder().encode(user.id),
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({ id: p.id, transports: p.transports as AuthenticatorTransport[] })),
      // A discoverable credential lets people sign in without typing an email;
      // user verification (PIN or biometrics) makes it count as two factors.
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
  }

  async verifyRegistration(response: RegistrationResponseJSON, expectedChallenge: string) {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      requireUserVerification: true,
    });
    if (!result.verified) return undefined;
    const info = result.registrationInfo;
    return {
      id: info.credential.id,
      publicKey: info.credential.publicKey,
      counter: info.credential.counter,
      transports: info.credential.transports ?? [],
      backupEligible: info.credentialDeviceType === 'multiDevice',
      backedUp: info.credentialBackedUp,
    };
  }

  // Without `allow`, any passkey of this site can answer (usernameless sign-in).
  authenticationOptions(allow: Passkey[] = []) {
    return generateAuthenticationOptions({
      rpID: this.rpID,
      userVerification: 'required',
      allowCredentials: allow.map((p) => ({ id: p.id, transports: p.transports as AuthenticatorTransport[] })),
    });
  }

  // Throws when the response is invalid, including when the sign counter did
  // not go up (a sign of a cloned authenticator).
  async verifyAuthentication(response: AuthenticationResponseJSON, expectedChallenge: string, passkey: Passkey) {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      requireUserVerification: true,
      credential: { id: passkey.id, publicKey: passkey.publicKey, counter: passkey.counter, transports: passkey.transports as AuthenticatorTransport[] },
    });
    if (!result.verified) return undefined;
    return { counter: result.authenticationInfo.newCounter, backedUp: result.authenticationInfo.credentialBackedUp };
  }
}

// RFC 8176: a synced passkey leaves the device, so it is reported as a
// software-secured key; otherwise as a hardware-secured key.
export const passkeyAmr = (backedUp: boolean) => (backedUp ? 'swk' : 'hwk');
