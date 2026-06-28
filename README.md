# crypto-lab-pq-tls-handshake

## What It Is

Browser-based simulation of the TLS 1.3 handshake using the X25519MLKEM768 hybrid post-quantum key exchange per draft-ietf-tls-ecdhe-mlkem-04 (February 2026, named group codepoint 0x11EC).

This project demonstrates both sides of a TLS 1.3 handshake entirely in-browser (no backend server) using the hybrid key exchange `X25519MLKEM768`:

- Client key share construction:
  - `X25519_pub (32)` + `ML-KEM-768_pub (1184)` = `1216` bytes
- Server key share construction:
  - `X25519_pub (32)` + `ML-KEM-768_ciphertext (1088)` = `1120` bytes
- Hybrid secret:
  - `X25519_shared (32)` + `ML-KEM_shared (32)` = `64` bytes

The hybrid shared secret is fed into the standard TLS 1.3 key schedule (RFC 8446 Section 7.1) via `HKDF-Extract` and `HKDF-Expand-Label` exactly as TLS expects for `(EC)DHE` input.

Everything shown is real, not mocked:

- The **wire-format inspector** dumps the actual serialized `ClientHello`; every byte offset and length (including the `0x11EC` group position) is computed from the real message, not hardcoded.
- The **classical X25519 comparison** is serialized through the exact same encoder, so the size difference is genuinely measured rather than asserted.
- The **compute cost** is timed live in your browser with `performance.now()` over real keygen / encapsulation / decapsulation — reported as the minimum across samples. (The dominant real-world post-quantum cost is the extra bytes on the wire — ~1.1 KB added to the `ClientHello` alone, ~2.3 KB across both hellos — not these sub-millisecond computations, and the UI says so.)
- All randomness comes from `crypto.getRandomValues` — a CI gate fails the build if `Math.random` ever appears in `src/`.

## When to Use It

Use this demo when you want to:

- Understand what modern browsers and CDNs are negotiating on real HTTPS connections today
- Teach hybrid PQ migration strategy for TLS 1.3 deployments
- Inspect byte-level handshake framing and the `0x11EC` group on the wire
- Study why TLS 1.3 key schedule logic does not need protocol changes for hybrid shared secrets
- Compare classical and hybrid handshake size/latency behavior in a single interactive tool
- Do NOT use this for production TLS — this is an educational simulation, not a hardened TLS stack. For production, use established libraries and runtimes.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/)**

The demo runs both client and server sides of an X25519MLKEM768 TLS 1.3 handshake in the browser. A wire-format inspector dumps the real serialized `ClientHello` with every byte offset and length (including the `0x11EC` group position), a classical X25519 comparison serialized through the same encoder shows the measured size difference, and live `performance.now()` timing reports real keygen / encapsulation / decapsulation cost. The hybrid shared secret feeds the standard RFC 8446 key schedule unchanged, illustrating why TLS 1.3 needs no protocol changes to adopt hybrid PQC.

## What Can Go Wrong

- **ClientHello fragmentation**: 1216-byte key-share payloads can push handshake messages near MTU boundaries and trigger fragmentation-sensitive middleboxes.
- **Implementation side-channels**: educational code in JavaScript/TypeScript is not constant-time and is not suitable for protecting long-term secrets.
- **Downgrade and interoperability pitfalls**: mismatched group support, extension handling, or middlebox tampering can force non-hybrid paths.
- **Future cryptanalytic surprises**: hybrid protects if at least one primitive survives, but assumptions still need continuous review and patching.
- **Slow-link latency amplification**: larger hello messages can increase handshake latency more noticeably on constrained or high-loss networks.

## Real-World Usage

- `X25519MLKEM768` (`0x11EC`) is specified in `draft-ietf-tls-ecdhe-mlkem-04` and replaces early deployment identifiers such as `X25519Kyber768Draft00` (`0x6399`, deprecated).
- As of mid-September 2025, Cloudflare reported approximately 43% of human-generated HTTPS connections using hybrid post-quantum key exchange.
- Chrome enabled hybrid by default in M124, and support also exists in Firefox, Edge, Brave, and Opera.
- This makes hybrid PQ TLS one of the most broadly deployed post-quantum cryptographic mechanisms in active internet use.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-pq-tls-handshake
cd crypto-lab-pq-tls-handshake
npm install
npm run dev
```

## Related Demos
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — X25519 + ML-KEM-768 with HKDF and AES-256-GCM, the same hybrid handshake outside TLS framing.
- [crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/) — KEM combiners (X-Wing) and how classical and PQ shared secrets are safely mixed.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203) on its own, the PQ half of this handshake.
- [crypto-lab-key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) — Diffie-Hellman, ECDH, X25519, and ML-KEM key exchange fundamentals.
- [crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/) — the operational migration plan that rolls hybrid TLS into production.

## Verification

```bash
npm run typecheck   # tsc strict, no emit
npm test            # crypto + handshake gates (RFC 8448 vectors, 100x round-trip, sizes, source scan)
npm run build       # type-check + production bundle
```

`npm test` runs every gate in `scripts/phase-checks.ts`, including the RFC 8448
`HKDF-Expand-Label` test vector, a 100-iteration client/server agreement loop,
exact key-share sizes (1216 / 1120 / 64 bytes), a live compute measurement, and
a source scan that rejects `Math.random`. The same gates run in CI
(`.github/workflows/deploy.yml`) and **must pass before GitHub Pages deploys**.

## License

[MIT](LICENSE) © Paul Clark (systemslibrarian)

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
