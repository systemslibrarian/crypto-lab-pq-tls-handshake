import {
  CLIENT_KEYSHARE_BYTES,
  HYBRID_SHARED_BYTES,
  SERVER_KEYSHARE_BYTES,
  concatBytes,
  deriveSecret,
  equalBytes,
  hkdfExtract,
  sha256,
  type MLKEM768Keypair,
  type X25519Keypair,
  mlkem768Keygen,
  x25519Keygen,
  x25519SharedSecret,
} from './primitives';
import {
  buildClientKeyShare,
  clientComputeHybridSecret,
  serverRespondToKeyShare,
  verifyAgreement,
} from './hybrid';

const TLS13 = 0x0304;
const TLS12_LEGACY_VERSION = 0x0303;
const RECORD_TLS12 = 0x0301;
const HANDSHAKE_CONTENT_TYPE = 0x16;
const CLIENT_HELLO_TYPE = 0x01;
const SERVER_HELLO_TYPE = 0x02;
const GROUP_X25519MLKEM768 = 0x11ec;
const GROUP_X25519 = 0x001d;
const CIPHER_TLS_AES_128_GCM_SHA256 = 0x1301;

export interface ClientHello {
  version: number;
  random: Uint8Array;
  legacy_session_id: Uint8Array;
  cipher_suites: number[];
  extensions: {
    supported_versions: number[];
    supported_groups: number[];
    key_share: {
      group: number;
      key_exchange: Uint8Array;
    };
  };
  rawBytes: Uint8Array;
}

export interface ServerHello {
  version: number;
  random: Uint8Array;
  legacy_session_id_echo: Uint8Array;
  cipher_suite: number;
  extensions: {
    supported_versions: number;
    key_share: {
      group: number;
      key_exchange: Uint8Array;
    };
  };
  rawBytes: Uint8Array;
}

export interface HandshakeResult {
  clientHello: ClientHello;
  serverHello: ServerHello;
  hybridShared: Uint8Array;
  /** First 32 bytes of hybridShared: the X25519 (classical ECDH) component. */
  x25519Component: Uint8Array;
  /** Last 32 bytes of hybridShared: the ML-KEM-768 (post-quantum) component. */
  mlkemComponent: Uint8Array;
  /** The server's independently computed 64-byte secret; must equal hybridShared. */
  serverHybridShared: Uint8Array;
  /** Whether client and server arrived at the same 64-byte secret (always true here). */
  secretsAgree: boolean;
  earlySecret: Uint8Array;
  /** "derived" secret between Early and Handshake secrets in the RFC 8446 schedule. */
  derivedSecret: Uint8Array;
  handshakeSecret: Uint8Array;
  clientHandshakeTrafficSecret: Uint8Array;
  serverHandshakeTrafficSecret: Uint8Array;
  transcriptHash: Uint8Array;
  totalBytes: number;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

function u24(value: number): Uint8Array {
  return new Uint8Array([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}

function encodeVector(payload: Uint8Array, bytes: 1 | 2): Uint8Array {
  if (bytes === 1) {
    if (payload.length > 255) {
      throw new Error('Vector too large for uint8 length');
    }
    return concatBytes(new Uint8Array([payload.length]), payload);
  }
  if (payload.length > 0xffff) {
    throw new Error('Vector too large for uint16 length');
  }
  return concatBytes(u16(payload.length), payload);
}

function encodeExtension(type: number, data: Uint8Array): Uint8Array {
  return concatBytes(u16(type), encodeVector(data, 2));
}

function buildHandshakeRecord(handshakeType: number, body: Uint8Array): Uint8Array {
  const handshake = concatBytes(new Uint8Array([handshakeType]), u24(body.length), body);
  return concatBytes(new Uint8Array([HANDSHAKE_CONTENT_TYPE]), u16(RECORD_TLS12), u16(handshake.length), handshake);
}

function serializeClientHello(clientHello: Omit<ClientHello, 'rawBytes'>): Uint8Array {
  const cipherBytes = new Uint8Array(clientHello.cipher_suites.length * 2);
  for (let i = 0; i < clientHello.cipher_suites.length; i += 1) {
    const suite = clientHello.cipher_suites[i];
    cipherBytes[i * 2] = (suite >> 8) & 0xff;
    cipherBytes[i * 2 + 1] = suite & 0xff;
  }

  const supportedVersionsPayload = concatBytes(new Uint8Array([2]), u16(clientHello.extensions.supported_versions[0]));
  const supportedGroupsPayload = encodeVector(
    concatBytes(...clientHello.extensions.supported_groups.map((group) => u16(group))),
    2,
  );

  const keyExchange = clientHello.extensions.key_share.key_exchange;
  const keyShareEntry = concatBytes(
    u16(clientHello.extensions.key_share.group),
    u16(keyExchange.length),
    keyExchange,
  );
  const keySharePayload = encodeVector(keyShareEntry, 2);

  const extensions = concatBytes(
    encodeExtension(0x002b, supportedVersionsPayload),
    encodeExtension(0x000a, supportedGroupsPayload),
    encodeExtension(0x0033, keySharePayload),
  );

  const body = concatBytes(
    u16(clientHello.version),
    clientHello.random,
    encodeVector(clientHello.legacy_session_id, 1),
    encodeVector(cipherBytes, 2),
    new Uint8Array([1, 0]),
    encodeVector(extensions, 2),
  );

  return buildHandshakeRecord(CLIENT_HELLO_TYPE, body);
}

function serializeServerHello(serverHello: Omit<ServerHello, 'rawBytes'>): Uint8Array {
  const supportedVersionsPayload = u16(serverHello.extensions.supported_versions);
  const keyExchange = serverHello.extensions.key_share.key_exchange;
  const keySharePayload = concatBytes(
    u16(serverHello.extensions.key_share.group),
    u16(keyExchange.length),
    keyExchange,
  );

  const extensions = concatBytes(
    encodeExtension(0x002b, supportedVersionsPayload),
    encodeExtension(0x0033, keySharePayload),
  );

  const body = concatBytes(
    u16(serverHello.version),
    serverHello.random,
    encodeVector(serverHello.legacy_session_id_echo, 1),
    u16(serverHello.cipher_suite),
    new Uint8Array([0]),
    encodeVector(extensions, 2),
  );

  return buildHandshakeRecord(SERVER_HELLO_TYPE, body);
}

export async function buildClientHello(): Promise<{
  clientHello: ClientHello;
  x25519: X25519Keypair;
  mlkem: MLKEM768Keypair;
}> {
  const x25519 = x25519Keygen();
  const mlkem = mlkem768Keygen();
  const { keyShare } = buildClientKeyShare(x25519, mlkem);

  if (keyShare.length !== CLIENT_KEYSHARE_BYTES) {
    throw new Error(`Client key share must be ${CLIENT_KEYSHARE_BYTES} bytes`);
  }

  const noRaw: Omit<ClientHello, 'rawBytes'> = {
    version: TLS12_LEGACY_VERSION,
    random: randomBytes(32),
    legacy_session_id: new Uint8Array(),
    cipher_suites: [CIPHER_TLS_AES_128_GCM_SHA256],
    extensions: {
      supported_versions: [TLS13],
      supported_groups: [GROUP_X25519MLKEM768, GROUP_X25519],
      key_share: {
        group: GROUP_X25519MLKEM768,
        key_exchange: keyShare,
      },
    },
  };

  const rawBytes = serializeClientHello(noRaw);
  return { clientHello: { ...noRaw, rawBytes }, x25519, mlkem };
}

export async function buildServerHello(
  clientHello: ClientHello,
): Promise<{
  serverHello: ServerHello;
  serverHybridShared: Uint8Array;
}> {
  if (clientHello.extensions.key_share.group !== GROUP_X25519MLKEM768) {
    throw new Error('Unsupported group: expected X25519MLKEM768 (0x11EC)');
  }

  const {
    serverKeyShare,
    serverHybridShared,
  } = serverRespondToKeyShare(clientHello.extensions.key_share.key_exchange);

  if (serverKeyShare.length !== SERVER_KEYSHARE_BYTES) {
    throw new Error(`Server key share must be ${SERVER_KEYSHARE_BYTES} bytes`);
  }

  const noRaw: Omit<ServerHello, 'rawBytes'> = {
    version: TLS12_LEGACY_VERSION,
    random: randomBytes(32),
    legacy_session_id_echo: clientHello.legacy_session_id,
    cipher_suite: CIPHER_TLS_AES_128_GCM_SHA256,
    extensions: {
      supported_versions: TLS13,
      key_share: {
        group: GROUP_X25519MLKEM768,
        key_exchange: serverKeyShare,
      },
    },
  };

  const rawBytes = serializeServerHello(noRaw);
  return { serverHello: { ...noRaw, rawBytes }, serverHybridShared };
}

export async function clientProcessServerHello(
  serverHello: ServerHello,
  clientHello: ClientHello,
  x25519: X25519Keypair,
  mlkem: MLKEM768Keypair,
  serverHybridShared: Uint8Array,
): Promise<HandshakeResult> {
  const { hybridShared, x25519Component, mlkemComponent } = clientComputeHybridSecret(
    serverHello.extensions.key_share.key_exchange,
    x25519,
    mlkem,
  );
  if (hybridShared.length !== HYBRID_SHARED_BYTES) {
    throw new Error(`Hybrid shared secret must be ${HYBRID_SHARED_BYTES} bytes`);
  }

  const secretsAgree = equalBytes(hybridShared, serverHybridShared);

  const transcript = concatBytes(clientHello.rawBytes, serverHello.rawBytes);
  const transcriptHash = await sha256(transcript);

  const zeros = new Uint8Array(32);
  const psk = new Uint8Array();

  // RFC 8446 §7.1 key schedule, run verbatim: the hybrid secret is fed in as
  // the (EC)DHE input to HKDF-Extract exactly where a classical shared secret
  // would go — this is the "no protocol change" property, made concrete.
  const earlySecret = await hkdfExtract(zeros, psk);
  const derivedSecret = await deriveSecret(earlySecret, 'derived', new Uint8Array());
  const handshakeSecret = await hkdfExtract(derivedSecret, hybridShared);
  const clientHandshakeTrafficSecret = await deriveSecret(handshakeSecret, 'c hs traffic', transcript);
  const serverHandshakeTrafficSecret = await deriveSecret(handshakeSecret, 's hs traffic', transcript);

  const totalBytes = clientHello.rawBytes.length + serverHello.rawBytes.length;

  return {
    clientHello,
    serverHello,
    hybridShared,
    x25519Component,
    mlkemComponent,
    serverHybridShared,
    secretsAgree,
    earlySecret,
    derivedSecret,
    handshakeSecret,
    clientHandshakeTrafficSecret,
    serverHandshakeTrafficSecret,
    transcriptHash,
    totalBytes,
  };
}

export async function runFullHandshake(): Promise<HandshakeResult> {
  const { clientHello, x25519, mlkem } = await buildClientHello();
  const { serverHello, serverHybridShared } = await buildServerHello(clientHello);
  const result = await clientProcessServerHello(serverHello, clientHello, x25519, mlkem, serverHybridShared);

  if (!result.secretsAgree) {
    throw new Error('Client/server hybrid shared secret mismatch');
  }
  return result;
}

/**
 * Build a real, byte-for-byte X25519-only TLS 1.3 handshake through the exact
 * same serializer as the hybrid path, so the size comparison reflects genuine
 * wire bytes rather than a guessed constant. The only differences from the
 * hybrid ClientHello are the advertised group (0x001D) and the 32-byte key
 * share, keeping the comparison apples-to-apples.
 */
export async function runClassicalHandshake(): Promise<{
  clientHelloBytes: number;
  serverHelloBytes: number;
  totalBytes: number;
}> {
  const clientX25519 = x25519Keygen();
  const clientHello: Omit<ClientHello, 'rawBytes'> = {
    version: TLS12_LEGACY_VERSION,
    random: randomBytes(32),
    legacy_session_id: new Uint8Array(),
    cipher_suites: [CIPHER_TLS_AES_128_GCM_SHA256],
    extensions: {
      supported_versions: [TLS13],
      supported_groups: [GROUP_X25519],
      key_share: { group: GROUP_X25519, key_exchange: clientX25519.publicKey },
    },
  };

  const serverX25519 = x25519Keygen();
  const serverHello: Omit<ServerHello, 'rawBytes'> = {
    version: TLS12_LEGACY_VERSION,
    random: randomBytes(32),
    legacy_session_id_echo: new Uint8Array(),
    cipher_suite: CIPHER_TLS_AES_128_GCM_SHA256,
    extensions: {
      supported_versions: TLS13,
      key_share: { group: GROUP_X25519, key_exchange: serverX25519.publicKey },
    },
  };

  const clientHelloBytes = serializeClientHello(clientHello).length;
  const serverHelloBytes = serializeServerHello(serverHello).length;
  return { clientHelloBytes, serverHelloBytes, totalBytes: clientHelloBytes + serverHelloBytes };
}

/**
 * Measure the actual key-exchange compute cost in the current runtime. Each
 * sample runs a complete key agreement (both peers); we report the minimum
 * across samples, the standard way to filter scheduler noise from a microbench.
 *
 * This times CPU only. In the real world the dominant post-quantum cost is the
 * ~1.1 KB of extra bytes on the wire, not these sub-millisecond computations —
 * a point the UI makes explicitly so the number is not over-read.
 */
export function benchmarkKeyExchange(samples = 16): {
  classicalMs: number;
  hybridMs: number;
  samples: number;
} {
  const classicalOp = (): void => {
    const c = x25519Keygen();
    const s = x25519Keygen();
    x25519SharedSecret(c.secretKey, s.publicKey);
    x25519SharedSecret(s.secretKey, c.publicKey);
  };

  const hybridOp = (): void => {
    const x = x25519Keygen();
    const m = mlkem768Keygen();
    const client = buildClientKeyShare(x, m);
    const server = serverRespondToKeyShare(client.keyShare);
    clientComputeHybridSecret(server.serverKeyShare, x, m);
  };

  const minOf = (op: () => void): number => {
    op(); // warm up JIT / caches before timing
    let best = Number.POSITIVE_INFINITY;
    for (let i = 0; i < samples; i += 1) {
      const start = performance.now();
      op();
      best = Math.min(best, performance.now() - start);
    }
    return best;
  };

  return { classicalMs: minOf(classicalOp), hybridMs: minOf(hybridOp), samples };
}

export function assertHybridAgreement(client: Uint8Array, server: Uint8Array): void {
  if (!verifyAgreement(client, server)) {
    throw new Error('Hybrid agreement failed');
  }
}

export const TLS_CONSTANTS = {
  TLS13,
  GROUP_X25519MLKEM768,
  GROUP_X25519,
  CIPHER_TLS_AES_128_GCM_SHA256,
};
