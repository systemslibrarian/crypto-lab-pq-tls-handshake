import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export const X25519_BYTES = 32;
export const MLKEM768_PUBKEY_BYTES = 1184;
export const MLKEM768_CIPHERTEXT_BYTES = 1088;
export const MLKEM768_SECRET_BYTES = 32;

export const CLIENT_KEYSHARE_BYTES = X25519_BYTES + MLKEM768_PUBKEY_BYTES;
export const SERVER_KEYSHARE_BYTES = X25519_BYTES + MLKEM768_CIPHERTEXT_BYTES;
export const HYBRID_SHARED_BYTES = 2 * X25519_BYTES;

const HASH_ALGO = 'SHA-256';
const HASH_SIZE = 32;
const HMAC_ALGO = 'HMAC';

export interface X25519Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface MLKEM768Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function ensureLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes, got ${bytes.length}`);
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = Uint8Array.from(bytes);
  return copy.buffer;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(HASH_ALGO, toArrayBuffer(data));
  return new Uint8Array(digest);
}

async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), { name: HMAC_ALGO, hash: HASH_ALGO }, false, ['sign']);
  const mac = await crypto.subtle.sign(HMAC_ALGO, key, toArrayBuffer(data));
  return new Uint8Array(mac);
}

export function x25519Keygen(): X25519Keypair {
  const secretKey = randomBytes(X25519_BYTES);
  const publicKey = x25519.getPublicKey(secretKey);
  ensureLength(publicKey, X25519_BYTES, 'X25519 public key');
  return { secretKey, publicKey };
}

export function x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  ensureLength(secretKey, X25519_BYTES, 'X25519 secret key');
  ensureLength(peerPublicKey, X25519_BYTES, 'X25519 peer public key');
  const shared = x25519.getSharedSecret(secretKey, peerPublicKey);
  ensureLength(shared, X25519_BYTES, 'X25519 shared secret');
  return shared;
}

export function mlkem768Keygen(): MLKEM768Keypair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  ensureLength(publicKey, MLKEM768_PUBKEY_BYTES, 'ML-KEM-768 public key');
  return { publicKey, secretKey };
}

export function mlkem768Encapsulate(publicKey: Uint8Array): {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
} {
  ensureLength(publicKey, MLKEM768_PUBKEY_BYTES, 'ML-KEM-768 public key');
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  ensureLength(cipherText, MLKEM768_CIPHERTEXT_BYTES, 'ML-KEM-768 ciphertext');
  ensureLength(sharedSecret, MLKEM768_SECRET_BYTES, 'ML-KEM-768 shared secret');
  return { ciphertext: cipherText, sharedSecret };
}

export function mlkem768Decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  ensureLength(ciphertext, MLKEM768_CIPHERTEXT_BYTES, 'ML-KEM-768 ciphertext');
  const shared = ml_kem768.decapsulate(ciphertext, secretKey);
  ensureLength(shared, MLKEM768_SECRET_BYTES, 'ML-KEM-768 decapsulated secret');
  return shared;
}

export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const mac = await hmacSha256(salt, ikm);
  ensureLength(mac, HASH_SIZE, 'HKDF-Extract output');
  return mac;
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  if (length <= 0) {
    return new Uint8Array();
  }

  const blocks = Math.ceil(length / HASH_SIZE);
  if (blocks > 255) {
    throw new Error('HKDF-Expand length too large');
  }

  const output = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;

  for (let i = 1; i <= blocks; i += 1) {
    const input = concatBytes(previous, info, new Uint8Array([i]));
    previous = Uint8Array.from(await hmacSha256(prk, input));
    const remaining = length - offset;
    const take = Math.min(remaining, previous.length);
    output.set(previous.subarray(0, take), offset);
    offset += take;
  }

  return output;
}

export async function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (length < 0 || length > 0xffff) {
    throw new Error(`Invalid HKDF-Expand-Label length: ${length}`);
  }

  const prefixedLabel = `tls13 ${label}`;
  const labelBytes = new TextEncoder().encode(prefixedLabel);
  if (labelBytes.length > 255) {
    throw new Error('TLS 1.3 label is too long');
  }
  if (context.length > 255) {
    throw new Error('TLS 1.3 context is too long');
  }

  const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
  hkdfLabel[0] = (length >> 8) & 0xff;
  hkdfLabel[1] = length & 0xff;
  hkdfLabel[2] = labelBytes.length;
  hkdfLabel.set(labelBytes, 3);
  hkdfLabel[3 + labelBytes.length] = context.length;
  hkdfLabel.set(context, 4 + labelBytes.length);

  return hkdfExpand(secret, hkdfLabel, length);
}

export async function deriveSecret(secret: Uint8Array, label: string, messages: Uint8Array): Promise<Uint8Array> {
  const transcriptHash = await sha256(messages);
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_SIZE);
}
