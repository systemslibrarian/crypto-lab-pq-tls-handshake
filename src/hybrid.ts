import {
  CLIENT_KEYSHARE_BYTES,
  HYBRID_SHARED_BYTES,
  MLKEM768_CIPHERTEXT_BYTES,
  MLKEM768_PUBKEY_BYTES,
  SERVER_KEYSHARE_BYTES,
  X25519_BYTES,
  concatBytes,
  equalBytes,
  mlkem768Decapsulate,
  mlkem768Encapsulate,
  x25519Keygen,
  x25519SharedSecret,
  type MLKEM768Keypair,
  type X25519Keypair,
} from './primitives';

function assertLength(bytes: Uint8Array, expected: number, label: string): void {
  if (bytes.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes, got ${bytes.length}`);
  }
}

export function buildClientKeyShare(
  x25519: X25519Keypair,
  mlkem: MLKEM768Keypair,
): {
  keyShare: Uint8Array;
  bytes: number;
} {
  assertLength(x25519.publicKey, X25519_BYTES, 'Client X25519 public key');
  assertLength(mlkem.publicKey, MLKEM768_PUBKEY_BYTES, 'Client ML-KEM public key');

  const keyShare = concatBytes(x25519.publicKey, mlkem.publicKey);
  assertLength(keyShare, CLIENT_KEYSHARE_BYTES, 'Client key share');
  return { keyShare, bytes: keyShare.length };
}

export function parseServerKeyShare(keyShare: Uint8Array): {
  serverX25519Pub: Uint8Array;
  mlkemCiphertext: Uint8Array;
} {
  assertLength(keyShare, SERVER_KEYSHARE_BYTES, 'Server key share');
  const serverX25519Pub = keyShare.subarray(0, X25519_BYTES);
  const mlkemCiphertext = keyShare.subarray(X25519_BYTES);
  assertLength(serverX25519Pub, X25519_BYTES, 'Server X25519 public key');
  assertLength(mlkemCiphertext, MLKEM768_CIPHERTEXT_BYTES, 'Server ML-KEM ciphertext');
  return { serverX25519Pub, mlkemCiphertext };
}

export function serverRespondToKeyShare(clientKeyShare: Uint8Array): {
  serverKeyShare: Uint8Array;
  serverHybridShared: Uint8Array;
  serverX25519: X25519Keypair;
  mlkemCiphertext: Uint8Array;
  mlkemSharedSecret: Uint8Array;
  x25519SharedSecret: Uint8Array;
} {
  assertLength(clientKeyShare, CLIENT_KEYSHARE_BYTES, 'Client key share');

  const clientX25519Pub = clientKeyShare.subarray(0, X25519_BYTES);
  const clientMlkemPub = clientKeyShare.subarray(X25519_BYTES);

  const serverX25519 = x25519Keygen();
  const x25519Shared = x25519SharedSecret(serverX25519.secretKey, clientX25519Pub);
  const { ciphertext, sharedSecret } = mlkem768Encapsulate(clientMlkemPub);

  const serverHybridShared = concatBytes(x25519Shared, sharedSecret);
  assertLength(serverHybridShared, HYBRID_SHARED_BYTES, 'Server hybrid shared secret');

  const serverKeyShare = concatBytes(serverX25519.publicKey, ciphertext);
  assertLength(serverKeyShare, SERVER_KEYSHARE_BYTES, 'Server key share');

  return {
    serverKeyShare,
    serverHybridShared,
    serverX25519,
    mlkemCiphertext: ciphertext,
    mlkemSharedSecret: sharedSecret,
    x25519SharedSecret: x25519Shared,
  };
}

export function clientComputeHybridSecret(
  serverKeyShare: Uint8Array,
  clientX25519: X25519Keypair,
  clientMLKEM: MLKEM768Keypair,
): {
  hybridShared: Uint8Array;
  x25519Component: Uint8Array;
  mlkemComponent: Uint8Array;
} {
  const { serverX25519Pub, mlkemCiphertext } = parseServerKeyShare(serverKeyShare);
  const x25519Component = x25519SharedSecret(clientX25519.secretKey, serverX25519Pub);
  const mlkemComponent = mlkem768Decapsulate(mlkemCiphertext, clientMLKEM.secretKey);
  const hybridShared = concatBytes(x25519Component, mlkemComponent);

  assertLength(hybridShared, HYBRID_SHARED_BYTES, 'Client hybrid shared secret');

  return { hybridShared, x25519Component, mlkemComponent };
}

export function verifyAgreement(clientHybrid: Uint8Array, serverHybrid: Uint8Array): boolean {
  assertLength(clientHybrid, HYBRID_SHARED_BYTES, 'Client hybrid secret');
  assertLength(serverHybrid, HYBRID_SHARED_BYTES, 'Server hybrid secret');
  return equalBytes(clientHybrid, serverHybrid);
}
