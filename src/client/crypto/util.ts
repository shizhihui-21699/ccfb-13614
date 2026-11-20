// Encoding / serialization helpers shared by browser and Node.
// All wire-format binary data is represented as base64 strings inside JSON.

/**
 * A Uint8Array backed by a plain ArrayBuffer (not SharedArrayBuffer), which is
 * what the WebCrypto BufferSource parameters require under the TS 5.7 lib defs.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

function asBytes(u: Uint8Array): Bytes {
  return u.buffer instanceof ArrayBuffer ? (u as Bytes) : new Uint8Array(u);
}

export function bytesToB64(bytes: Uint8Array): string {
  const g = globalThis as { Buffer?: { from(b: Uint8Array): { toString(e: string): string } } };
  if (typeof g.Buffer !== "undefined") return g.Buffer.from(bytes).toString("base64");
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    const chunk = bytes.subarray(i, i + 0x8000);
    bin += String.fromCharCode(...chunk);
  }
  return btoa(bin);
}

export function b64ToBytes(b64: string): Bytes {
  const g = globalThis as { Buffer?: { from(s: string, e: string): Uint8Array } };
  if (typeof g.Buffer !== "undefined") return asBytes(new Uint8Array(g.Buffer.from(b64, "base64")));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(parts: Uint8Array[]): Bytes {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out: Bytes = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
export const utf8 = (s: string): Bytes => asBytes(encoder.encode(s));
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);

/** Deterministic JSON serialization with recursively sorted object keys. */
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJSON(v)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJSON(v)}`).join(",")}}`;
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
