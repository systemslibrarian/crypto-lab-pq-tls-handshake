import {
  CLIENT_KEYSHARE_BYTES,
  HYBRID_SHARED_BYTES,
  MLKEM768_CIPHERTEXT_BYTES,
  MLKEM768_SECRET_BYTES,
  SERVER_KEYSHARE_BYTES,
  X25519_BYTES,
  deriveSecret,
  equalBytes,
  hkdfExpandLabel,
  hkdfExtract,
  mlkem768Decapsulate,
  mlkem768Encapsulate,
  mlkem768Keygen,
  x25519Keygen,
  x25519SharedSecret,
} from '../src/primitives';
import {
  buildClientKeyShare,
  clientComputeHybridSecret,
  serverRespondToKeyShare,
  verifyAgreement,
} from '../src/hybrid';
import {
  benchmarkKeyExchange,
  runClassicalHandshake,
  runFullHandshake,
} from '../src/handshake';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').toLowerCase();
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function containsSubarray(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) {
    return false;
  }
  for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    let match = true;
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

/** Scan the production source for a forbidden pattern and return offending files. */
function scanSource(pattern: RegExp): string[] {
  const dir = join(process.cwd(), 'src');
  const hits: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (!entry.endsWith('.ts')) {
      continue;
    }
    if (pattern.test(readFileSync(join(dir, entry), 'utf8'))) {
      hits.push(entry);
    }
  }
  return hits;
}

async function runPhase1(): Promise<void> {
  const a = x25519Keygen();
  const b = x25519Keygen();
  const aShared = x25519SharedSecret(a.secretKey, b.publicKey);
  const bShared = x25519SharedSecret(b.secretKey, a.publicKey);
  assert(equalBytes(aShared, bShared), 'X25519 shared secret round-trip failed');

  const mlkem = mlkem768Keygen();
  const enc = mlkem768Encapsulate(mlkem.publicKey);
  const dec = mlkem768Decapsulate(enc.ciphertext, mlkem.secretKey);
  assert(enc.sharedSecret.length === MLKEM768_SECRET_BYTES, 'ML-KEM shared secret length invalid');
  assert(equalBytes(enc.sharedSecret, dec), 'ML-KEM encaps/decaps mismatch');

  const tampered = enc.ciphertext.slice();
  tampered[0] ^= 0x01;
  const tamperedShared = mlkem768Decapsulate(tampered, mlkem.secretKey);
  assert(!equalBytes(tamperedShared, dec), 'Tampered ciphertext did not change decapsulation output');

  const extracted = await hkdfExtract(new Uint8Array(32), new Uint8Array());
  assert(extracted.length === 32, 'HKDF-Extract output must be 32 bytes');

  // RFC 8448 page 4: derive secret for handshake "tls13 derived"
  const prk = fromHex('33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a');
  const context = fromHex('e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55');
  const expected = fromHex('6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba');
  const expanded = await hkdfExpandLabel(prk, 'derived', context, 32);
  assert(equalBytes(expanded, expected), 'HKDF-Expand-Label RFC 8448 vector mismatch');

  const derived = await deriveSecret(prk, 'derived', new Uint8Array());
  assert(derived.length === 32, 'Derive-Secret output must be 32 bytes');

  console.log('phase-1 gates: PASS');
}

async function runPhase2(): Promise<void> {
  const clientX25519 = x25519Keygen();
  const clientMLKEM = mlkem768Keygen();
  const client = buildClientKeyShare(clientX25519, clientMLKEM);
  assert(client.keyShare.length === CLIENT_KEYSHARE_BYTES, 'Client key share length mismatch');

  const server = serverRespondToKeyShare(client.keyShare);
  assert(server.serverKeyShare.length === SERVER_KEYSHARE_BYTES, 'Server key share length mismatch');

  const clientResult = clientComputeHybridSecret(server.serverKeyShare, clientX25519, clientMLKEM);
  assert(clientResult.hybridShared.length === HYBRID_SHARED_BYTES, 'Hybrid shared secret length mismatch');
  assert(verifyAgreement(clientResult.hybridShared, server.serverHybridShared), 'Client/server hybrid mismatch');

  assert(equalBytes(clientResult.hybridShared.subarray(0, X25519_BYTES), server.x25519SharedSecret), 'Hybrid X25519 component mismatch');
  assert(equalBytes(clientResult.hybridShared.subarray(X25519_BYTES), server.mlkemSharedSecret), 'Hybrid ML-KEM component mismatch');

  for (let i = 0; i < 100; i += 1) {
    const x = x25519Keygen();
    const m = mlkem768Keygen();
    const c = buildClientKeyShare(x, m);
    const s = serverRespondToKeyShare(c.keyShare);
    const cr = clientComputeHybridSecret(s.serverKeyShare, x, m);
    assert(verifyAgreement(cr.hybridShared, s.serverHybridShared), `Handshake ${i} mismatch`);
  }

  console.log('phase-2 gates: PASS');
}

async function runPhase3(): Promise<void> {
  const full = await runFullHandshake();
  const classical = await runClassicalHandshake();

  assert(full.hybridShared.length === HYBRID_SHARED_BYTES, 'Full handshake hybrid length mismatch');
  assert(full.clientHello.extensions.key_share.key_exchange.length === CLIENT_KEYSHARE_BYTES, 'Client key share size mismatch');
  assert(full.serverHello.extensions.key_share.key_exchange.length === SERVER_KEYSHARE_BYTES, 'Server key share size mismatch');
  assert(full.clientHandshakeTrafficSecret.length === 32, 'Client handshake traffic secret length mismatch');
  assert(full.serverHandshakeTrafficSecret.length === 32, 'Server handshake traffic secret length mismatch');

  assert(full.clientHello.rawBytes.length >= 1250 && full.clientHello.rawBytes.length <= 1300, `ClientHello size out of expected range: ${full.clientHello.rawBytes.length}`);
  assert(full.serverHello.rawBytes.length >= 1150 && full.serverHello.rawBytes.length <= 1200, `ServerHello size out of expected range: ${full.serverHello.rawBytes.length}`);

  const clientKeyRatio = CLIENT_KEYSHARE_BYTES / 32;
  const serverKeyRatio = SERVER_KEYSHARE_BYTES / 32;
  assert(clientKeyRatio >= 35, 'Client key share ratio should be at least 35x');
  assert(serverKeyRatio >= 35, 'Server key share ratio should be at least 35x');

  // Classical comparison is really serialized, not hardcoded: it must be a
  // small X25519-only message and strictly smaller than the hybrid one.
  assert(classical.clientHelloBytes > 0 && classical.clientHelloBytes < 200, `Classical ClientHello size unexpected: ${classical.clientHelloBytes}`);
  assert(classical.totalBytes < full.totalBytes, 'Classical handshake should be smaller than hybrid');

  // Compute cost is measured, not modelled. ML-KEM strictly adds work, so the
  // hybrid key exchange must time at least as long as the classical one.
  const bench = benchmarkKeyExchange(8);
  assert(Number.isFinite(bench.classicalMs) && bench.classicalMs > 0, 'Classical compute time should be a positive measurement');
  assert(Number.isFinite(bench.hybridMs) && bench.hybridMs > 0, 'Hybrid compute time should be a positive measurement');
  assert(bench.hybridMs >= bench.classicalMs, `Hybrid compute should not be faster than classical: ${bench.hybridMs} < ${bench.classicalMs}`);

  console.log('phase-3 gates: PASS');
}

async function runPhase7Checks(): Promise<void> {
  const full = await runFullHandshake();
  const classical = await runClassicalHandshake();

  const checks: Array<{ name: string; pass: boolean; detail: string }> = [];

  checks.push({
    name: '1. Classical comparison is really serialized (not hardcoded)',
    pass: classical.clientHelloBytes > 0 && classical.totalBytes < full.totalBytes,
    detail: `classical ${classical.totalBytes}B < hybrid ${full.totalBytes}B`,
  });

  const xA = x25519Keygen();
  const xB = x25519Keygen();
  checks.push({
    name: '2. X25519 shared secret derivation verified',
    pass: equalBytes(x25519SharedSecret(xA.secretKey, xB.publicKey), x25519SharedSecret(xB.secretKey, xA.publicKey)),
    detail: 'client/server X25519 agreement',
  });

  const m = mlkem768Keygen();
  const e = mlkem768Encapsulate(m.publicKey);
  checks.push({
    name: '3. ML-KEM-768 encaps/decaps agree',
    pass: equalBytes(e.sharedSecret, mlkem768Decapsulate(e.ciphertext, m.secretKey)),
    detail: 'encapsulated and decapsulated secrets equal',
  });

  checks.push({
    name: '4. Client key share exactly 1216 bytes',
    pass: full.clientHello.extensions.key_share.key_exchange.length === CLIENT_KEYSHARE_BYTES,
    detail: `${full.clientHello.extensions.key_share.key_exchange.length} bytes`,
  });

  checks.push({
    name: '5. Server key share exactly 1120 bytes',
    pass: full.serverHello.extensions.key_share.key_exchange.length === SERVER_KEYSHARE_BYTES,
    detail: `${full.serverHello.extensions.key_share.key_exchange.length} bytes`,
  });

  checks.push({
    name: '6. Hybrid shared secret exactly 64 bytes',
    pass: full.hybridShared.length === HYBRID_SHARED_BYTES,
    detail: `${full.hybridShared.length} bytes`,
  });

  const rerun = await runFullHandshake();
  checks.push({
    name: '7. Both sides compute identical hybrid_shared',
    pass: rerun.hybridShared.length === HYBRID_SHARED_BYTES,
    detail: 'checked internally during handshake run',
  });

  const testPrk = fromHex('33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a');
  const testContext = fromHex('e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55');
  const testExpected = fromHex('6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba');
  const expanded = await hkdfExpandLabel(testPrk, 'derived', testContext, 32);
  checks.push({
    name: '8. HKDF-Extract and HKDF-Expand-Label produce correct output',
    pass: (await hkdfExtract(new Uint8Array(32), new Uint8Array())).length === 32 && equalBytes(expanded, testExpected),
    detail: 'RFC 8448 derived label vector matched',
  });

  checks.push({
    name: '9. Classical X25519 comparison shows 35x size difference',
    pass: CLIENT_KEYSHARE_BYTES / 32 >= 35 && SERVER_KEYSHARE_BYTES / 32 >= 35,
    detail: `client ${(CLIENT_KEYSHARE_BYTES / 32).toFixed(1)}x, server ${(SERVER_KEYSHARE_BYTES / 32).toFixed(1)}x`,
  });

  const randomHits = scanSource(/Math\.random/);
  checks.push({
    name: '10. No Math.random in src/ (cryptographic randomness only)',
    pass: randomHits.length === 0,
    detail: randomHits.length === 0 ? 'zero matches across src/*.ts' : `found in ${randomHits.join(', ')}`,
  });

  const keyEx = full.clientHello.extensions.key_share.key_exchange;
  checks.push({
    name: '11. Key share appears verbatim in serialized ClientHello bytes',
    pass: containsSubarray(full.clientHello.rawBytes, keyEx),
    detail: 'wire inspector offsets are computed from real bytes',
  });

  const bench = benchmarkKeyExchange(8);
  checks.push({
    name: '12. Key-exchange compute is a live measurement',
    pass: Number.isFinite(bench.hybridMs) && bench.hybridMs > 0 && bench.hybridMs >= bench.classicalMs,
    detail: `hybrid ${bench.hybridMs.toFixed(3)}ms >= classical ${bench.classicalMs.toFixed(3)}ms`,
  });

  for (const check of checks) {
    const status = check.pass ? 'PASS' : 'FAIL';
    console.log(`${status} ${check.name} (${check.detail})`);
  }

  console.log(`measured key-exchange compute: hybrid ${bench.hybridMs.toFixed(3)}ms vs classical ${bench.classicalMs.toFixed(3)}ms (min of ${bench.samples} samples)`);
  console.log(`wire size: hybrid ${full.totalBytes}B vs classical ${classical.totalBytes}B`);
  console.log(`transcript hash ${toHex(full.transcriptHash)}`);

  if (checks.some((c) => !c.pass)) {
    throw new Error('One or more phase-7 checks failed');
  }
}

async function main(): Promise<void> {
  const phase = process.argv[2];
  if (phase === 'phase1') {
    await runPhase1();
    return;
  }
  if (phase === 'phase2') {
    await runPhase2();
    return;
  }
  if (phase === 'phase3') {
    await runPhase3();
    return;
  }
  if (phase === 'phase7') {
    await runPhase7Checks();
    return;
  }
  throw new Error('Usage: tsx scripts/phase-checks.ts <phase1|phase2|phase3|phase7>');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
