// A device identity: one signing keypair (authenticates commits/messages) and
// one ECDH keypair (receives epoch-secret envelopes).
//
// In a production client the private keys would be non-extractable and bound to
// a platform keystore (WebAuthn/TPM/Secure Enclave). They are exportable here so
// the demo can (a) persist simulated members in localStorage and (b) hand an
// *exported* keystore to the side-channel attacker tool to simulate device theft.

import {
  exportPrivateB64,
  exportPublicB64,
  exportSigningPublicSpki,
  generateECDHKey,
  generateSigningKey,
  importECDHPrivate,
  importECDHPublic,
  importSigningPrivate,
  importSigningPublic,
  memberId,
} from "./primitives.js";
import type { MemberPublic } from "./protocol.js";

export interface SerializedIdentity {
  id: string;
  displayName: string;
  sigPub: string; // SPKI b64
  sigPriv: string; // PKCS#8 b64
  ecdhPub: string; // raw point b64
  ecdhPriv: string; // PKCS#8 b64
}

export class DeviceIdentity {
  private constructor(
    readonly id: string,
    readonly displayName: string,
    readonly sigKey: CryptoKeyPair,
    readonly ecdhKey: CryptoKeyPair,
    readonly sigPubSpkiB64: string,
    readonly ecdhPubRawB64: string,
  ) {}

  static async create(displayName: string): Promise<DeviceIdentity> {
    const sigKey = await generateSigningKey();
    const ecdhKey = await generateECDHKey();
    const sigPubSpkiB64 = await exportSigningPublicSpki(sigKey.publicKey!);
    const id = await memberId(sigPubSpkiB64);
    return new DeviceIdentity(
      id,
      displayName,
      sigKey,
      ecdhKey,
      sigPubSpkiB64,
      await exportPublicB64(ecdhKey.publicKey!),
    );
  }

  async publicMember(): Promise<MemberPublic> {
    return { id: this.id, sigPub: this.sigPubSpkiB64, ecdhPub: this.ecdhPubRawB64 };
  }

  async serialize(): Promise<SerializedIdentity> {
    return {
      id: this.id,
      displayName: this.displayName,
      sigPub: this.sigPubSpkiB64,
      sigPriv: await exportPrivateB64(this.sigKey.privateKey!),
      ecdhPub: this.ecdhPubRawB64,
      ecdhPriv: await exportPrivateB64(this.ecdhKey.privateKey!),
    };
  }

  static async restore(data: SerializedIdentity): Promise<DeviceIdentity> {
    const sigKey = {
      publicKey: await importSigningPublic(data.sigPub),
      privateKey: await importSigningPrivate(data.sigPriv),
    } as CryptoKeyPair;
    const ecdhKey = {
      publicKey: await importECDHPublic(data.ecdhPub),
      privateKey: await importECDHPrivate(data.ecdhPriv),
    } as CryptoKeyPair;
    const id = await memberId(data.sigPub);
    if (id !== data.id) throw new Error("identity id does not match its signature public key");
    return new DeviceIdentity(id, data.displayName, sigKey, ecdhKey, data.sigPub, data.ecdhPub);
  }
}
