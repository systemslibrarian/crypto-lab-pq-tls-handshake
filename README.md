# crypto-lab-pq-tls-handshake

Browser-based simulation of the TLS 1.3 handshake using the X25519MLKEM768 hybrid post-quantum key exchange per draft-ietf-tls-ecdhe-mlkem-04 (February 2026, named group codepoint 0x11EC).

## What It Is

This project demonstrates both sides of a TLS 1.3 handshake entirely in-browser (no backend server) using the hybrid key exchange `X25519MLKEM768`:

- Client key share construction:
  - `X25519_pub (32)` + `ML-KEM-768_pub (1184)` = `1216` bytes
- Server key share construction:
  - `X25519_pub (32)` + `ML-KEM-768_ciphertext (1088)` = `1120` bytes
- Hybrid secret:
  - `X25519_shared (32)` + `ML-KEM_shared (32)` = `64` bytes

The hybrid shared secret is fed into the standard TLS 1.3 key schedule (RFC 8446 Section 7.1) via `HKDF-Extract` and `HKDF-Expand-Label` exactly as TLS expects for `(EC)DHE` input.

The app includes a side-by-side comparison against classical X25519-only TLS to visualize the size increase and latency impact.

## When to Use It

Use this demo when you want to:

- Understand what modern browsers and CDNs are negotiating on real HTTPS connections today
- Teach hybrid PQ migration strategy for TLS 1.3 deployments
- Inspect byte-level handshake framing and the `0x11EC` group on the wire
- Study why TLS 1.3 key schedule logic does not need protocol changes for hybrid shared secrets
- Compare classical and hybrid handshake size/latency behavior in a single interactive tool

Not for production TLS: this is an educational simulation, not a hardened TLS stack. For production, use established libraries and runtimes.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/

## What Can Go Wrong

- **ClientHello fragmentation**: 1216-byte key-share payloads can push handshake messages near MTU boundaries and trigger fragmentation-sensitive middleboxes.
- **Implementation side-channels**: educational code in JavaScript/TypeScript is not constant-time and is not suitable for protecting long-term secrets.
- **Downgrade and interoperability pitfalls**: mismatched group support, extension handling, or middlebox tampering can force non-hybrid paths.
- **Future cryptanalytic surprises**: hybrid protects if at least one primitive survives, but assumptions still need continuous review and patching.
- **Slow-link latency amplification**: larger hello messages can increase handshake latency more noticeably on constrained or high-loss networks.

## Real-World Usage

`X25519MLKEM768` (`0x11EC`) is specified in `draft-ietf-tls-ecdhe-mlkem-04` and replaces early deployment identifiers such as `X25519Kyber768Draft00` (`0x6399`, deprecated).

As of mid-September 2025, Cloudflare reported approximately 43% of human-generated HTTPS connections using hybrid post-quantum key exchange. Chrome enabled hybrid by default in M124, and support also exists in Firefox, Edge, Brave, and Opera.

This makes hybrid PQ TLS one of the most broadly deployed post-quantum cryptographic mechanisms in active internet use.

## Local Development

```bash
npm install
npm run dev
```

## Verification

```bash
npm run verify:phase1
npm run verify:phase2
npm run verify:phase3
npm run verify:phase7
npm run build
```
