// Low-level cryptographic primitives built on the WebCrypto API (SubtleCrypto).
// The exact same code runs in the browser and under Node >= 19 (globalThis.crypto).
//
// Curves/suites:
//   - ECDH P-256  : key encapsulation (ECIES) of epoch secrets
//   - ECDSA P-256 : authentication of commits and individual messages
//   - HKDF-SHA256 : key derivation / ratchets
//   - AES-256-GCM : message payload confidentiality + integrity

import { b64ToBytes, bytesToB64, bytesToHex, canonicalJSON, concatBytes, utf8, type Bytes } from "./util.js";

const subtle = globalThis.crypto.subtle;
const EC_P256 = { name: "ECDH", namedCurve: "P-256" } as const;
const SIG_P256 = { name: "ECDSA", namedCurve: "P-256" } as const;

export interface EciesEnvelope {
  /** ephemeral sender public key, raw uncompressed point, base64 */
  epk: string;
  /** 12-byte GCM nonce, base64 */
  iv: string;
  /** ciphertext || 16-byte GCM tag, base64 */
  ct: string;
}

export async function generateECDHKey(): Promise<CryptoKeyPair> {
  return subtle.generateKey(EC_P256, true, ["deriveBits"]) as Promise<CryptoKeyPair>;
}

export async function generateSigningKey(): Promise<CryptoKeyPair> {
  return subtle.generateKey(SIG_P256, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

// ---------- key (de)serialization ----------

export async function exportPublicRaw(key: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle.exportKey("raw", key));
}
export async function exportPublicB64(key: CryptoKey): Promise<string> {
  return bytesToB64(await exportPublicRaw(key));
}
export async function importECDHPublic(rawB64: string): Promise<CryptoKey> {
  return subtle.importKey("raw", b64ToBytes(rawB64), EC_P256, true, []);
}

export async function exportPrivateB64(key: CryptoKey): Promise<string> {
  const fmt = key.algorithm.name === "ECDSA" ? "pkcs8" : "pkcs8";
  return bytesToB64(new Uint8Array(await subtle.exportKey(fmt, key)));
}
export async function importECDHPrivate(pkcs8B64: string): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", b64ToBytes(pkcs8B64), EC_P256, true, ["deriveBits"]);
}
export async function importSigningPrivate(pkcs8B64: string): Promise<CryptoKey> {
  return subtle.importKey("pkcs8", b64ToBytes(pkcs8B64), SIG_P256, true, ["sign"]);
}
export async function importSigningPublic(spkiB64: string): Promise<CryptoKey> {
  // Signing public keys travel as SPKI; ECDH public keys travel as raw points.
  return subtle.importKey("spki", b64ToBytes(spkiB64), SIG_P256, true, ["verify"]);
}
export async function exportSigningPublicSpki(key: CryptoKey): Promise<string> {
  return bytesToB64(new Uint8Array(await subtle.exportKey("spki", key)));
}

/**
 * A member's identity is bound to its signature verification key:
 * id = first 16 bytes (hex) of SHA-256(SPKI(signingPublicKey)).
 * The server cannot re-map ids to different keys without breaking signature checks.
 */
export async function memberId(signingPublicKeySpkiB64: string): Promise<string> {
  const digest: Bytes = new Uint8Array(
    await subtle.digest("SHA-256", b64ToBytes(signingPublicKeySpkiB64)),
  );
  return bytesToHex(digest.subarray(0, 16));
}

// ---------- HKDF / random ----------

export function randomBytes(n: number): Bytes {
  const out: Bytes = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

export async function hkdf(
  ikm: Bytes,
  info: Bytes | string,
  length = 32,
  salt: Bytes = new Uint8Array(32),
): Promise<Bytes> {
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: typeof info === "string" ? utf8(info) : info,
    },
    await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]),
    length * 8,
  );
  return new Uint8Array(bits);
}

// ---------- ECIES (one-way ECDH KEM + AEAD) ----------

/** Encrypt `plaintext` for the holder of `recipientECDHPublicKey`. */
export async function eciesSeal(
  recipientECDHPublicKey: CryptoKey,
  plaintext: Bytes,
): Promise<EciesEnvelope> {
  const ephemeral = await generateECDHKey();
  const epub = await exportPublicRaw(ephemeral.publicKey!);
  const shared: Bytes = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: recipientECDHPublicKey }, ephemeral.privateKey!, 256),
  );
  const kek = await hkdf(shared, utf8("ECIES-v1/ecies-kek"), 32, epub);
  const iv = randomBytes(12);
  const ct = await aesGcmSeal(kek, iv, plaintext, epub);
  return { epk: bytesToB64(epub), iv: bytesToB64(iv), ct: bytesToB64(ct) };
}

/** Decrypt an ECIES envelope using the recipient's ECDH private key. */
export async function eciesOpen(
  recipientECDHPrivateKey: CryptoKey,
  env: EciesEnvelope,
): Promise<Bytes> {
  const epub = b64ToBytes(env.epk);
  const ephemeralPub = await importECDHPublic(env.epk);
  const shared: Bytes = new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: ephemeralPub }, recipientECDHPrivateKey, 256),
  );
  const kek = await hkdf(shared, utf8("ECIES-v1/ecies-kek"), 32, epub);
  return aesGcmOpen(kek, b64ToBytes(env.iv), b64ToBytes(env.ct), epub);
}

// ---------- AES-256-GCM ----------

async function importAesKey(key: Bytes): Promise<CryptoKey> {
  return subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function aesGcmSeal(
  key: Bytes,
  iv: Bytes,
  plaintext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  return new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, await importAesKey(key), plaintext),
  );
}

export async function aesGcmOpen(
  key: Bytes,
  iv: Bytes,
  ciphertext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  return new Uint8Array(
    await subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, await importAesKey(key), ciphertext),
  );
}

// ---------- signatures ----------

export async function sign(signingKey: CryptoKey, value: unknown): Promise<string> {
  const data = utf8(canonicalJSON(value));
  return bytesToB64(new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKey, data)));
}

export async function verify(
  verifyingKey: CryptoKey,
  value: unknown,
  signatureB64: string,
): Promise<boolean> {
  try {
    const data = utf8(canonicalJSON(value));
    return await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyingKey,
      b64ToBytes(signatureB64),
      data,
    );
  } catch {
    return false;
  }
}

// ---------- sender-key ratchet ----------

/** Derive a sender's initial chain key for an epoch from the epoch secret. */
export async function initChainKey(epochSecret: Bytes, senderId: string): Promise<Bytes> {
  return hkdf(epochSecret, utf8(`sender-chain/v1/${senderId}`), 32);
}

/** One ratchet step: derive the message key and the next chain key. */
export async function ratchet(chainKey: Bytes): Promise<{ messageKey: Bytes; nextChainKey: Bytes }> {
  const [messageKey, nextChainKey] = await Promise.all([
    hkdf(chainKey, "ratchet/v1/message-key", 32),
    hkdf(chainKey, "ratchet/v1/next-chain-key", 32),
  ]);
  return { messageKey, nextChainKey };
}

/** AAD binding a message to its group / epoch / sender / sequence position. */
export function messageAAD(groupId: string, epoch: number, senderId: string, generation: number): Bytes {
  return utf8(`group-msg/v1|${groupId}|${epoch}|${senderId}|${generation}`);
}

export { concatBytes };
