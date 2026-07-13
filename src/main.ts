import './style.css';
import {
  CLIENT_KEYSHARE_BYTES,
  SERVER_KEYSHARE_BYTES,
  X25519_BYTES,
  mlkem768Keygen,
  x25519Keygen,
} from './primitives';
import {
  buildClientKeyShare,
  clientComputeHybridSecret,
  serverRespondToKeyShare,
} from './hybrid';
import {
  TLS_CONSTANTS,
  benchmarkKeyExchange,
  buildClientHello,
  buildServerHello,
  runClassicalHandshake,
  runFullHandshake,
  type HandshakeResult,
} from './handshake';

interface SimulationState {
  phaseStep: number;
  result: HandshakeResult;
  classical: Awaited<ReturnType<typeof runClassicalHandshake>>;
  compute: ReturnType<typeof benchmarkKeyExchange>;
  showWireBytes: boolean;
  autoPlay: boolean;
  autoTimer: number | null;
  selectedInspector: 'group' | 'x25519' | 'mlkem';
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing app root');
}
const appRoot = app;

const state: SimulationState = {
  phaseStep: 1,
  result: await runFullHandshake(),
  classical: await runClassicalHandshake(),
  compute: benchmarkKeyExchange(),
  showWireBytes: false,
  autoPlay: false,
  autoTimer: null,
  selectedInspector: 'group',
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function preview(bytes: Uint8Array, front = 8, back = 8): string {
  if (bytes.length <= front + back) {
    return toHex(bytes);
  }
  return `${toHex(bytes.subarray(0, front))}...${toHex(bytes.subarray(bytes.length - back))}`;
}

function bytesMultiplier(bytes: number, base = 32): string {
  return `${(bytes / base).toFixed(1)}x`;
}

/** Escape a plain string for safe use as an HTML attribute value. */
function attr(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * A hoverable + keyboard-focusable glossary term. The definition is exposed
 * both visually (on hover/focus via title + the abbr's native tooltip) and to
 * assistive tech via aria-label, so the term carries its meaning without color.
 * A dotted underline signals "there's more here" independent of colour.
 */
function term(label: string, definition: string): string {
  const full = `${label}: ${definition}`;
  return `<abbr class="term" tabindex="0" title="${attr(full)}" aria-label="${attr(full)}">${label}</abbr>`;
}

/**
 * Render a byte preview as a coloured "capsule" of the given kind. Used by the
 * hybrid-secret exhibit so the same 32-byte value reads identically wherever it
 * appears. The kind label is always present as text (not colour alone).
 */
function secretCapsule(
  kind: 'x25519' | 'mlkem' | 'hybrid',
  title: string,
  bytesLen: number,
  hexPreview: string,
): string {
  return `
    <div class="capsule capsule-${kind}">
      <span class="capsule-title">${title}</span>
      <code class="capsule-hex">${hexPreview}</code>
      <span class="capsule-len">${bytesLen} bytes</span>
    </div>`;
}

async function regenerateSimulation(): Promise<void> {
  state.result = await runFullHandshake();
  state.classical = await runClassicalHandshake();
  state.compute = benchmarkKeyExchange();
  state.phaseStep = 1;
}

/** Locate a byte sub-sequence (the key share) inside the real serialized message. */
function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || needle.length > haystack.length) {
    return -1;
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
      return i;
    }
  }
  return -1;
}

function offsetLabel(index: number): string {
  return index.toString(16).padStart(4, '0');
}

/**
 * Render the actual ClientHello bytes as an offset-annotated hex dump. The
 * named group, X25519 public key, and ML-KEM-768 public key are colour-coded
 * in place; the bulk of the 1184-byte ML-KEM key is elided so the framing
 * stays legible. Every offset and length below is computed from the real
 * serialized message, not hardcoded.
 */
function renderHexDump(
  raw: Uint8Array,
  start: number,
  end: number,
  classify: (i: number) => '' | 'group' | 'x25519' | 'mlkem',
  selected: string,
): string {
  let out = '';
  for (let i = start; i < end; i += 1) {
    if (i === start || i % 16 === 0) {
      if (i !== start) {
        out += '\n';
      }
      out += `${offsetLabel(i)}  `;
    }
    const cls = classify(i);
    const hex = raw[i].toString(16).padStart(2, '0');
    if (cls) {
      const active = cls === selected ? ' active' : '';
      out += `<span class="${cls}${active}">${hex}</span> `;
    } else {
      out += `${hex} `;
    }
  }
  return out;
}

function createWireBytesBlock(result: HandshakeResult): string {
  const raw = result.clientHello.rawBytes;
  const keyEx = result.clientHello.extensions.key_share.key_exchange;
  const keyOffset = findSubarray(raw, keyEx);

  const groupClass = state.selectedInspector === 'group' ? 'active' : '';
  const xClass = state.selectedInspector === 'x25519' ? 'active' : '';
  const mClass = state.selectedInspector === 'mlkem' ? 'active' : '';

  const chips = `
    <div class="inspector-toggle">
      <button data-inspector="group" class="chip ${groupClass}" aria-pressed="${groupClass ? 'true' : 'false'}" aria-label="Highlight named group bytes 0x11EC">0x11EC group</button>
      <button data-inspector="x25519" class="chip ${xClass}" aria-pressed="${xClass ? 'true' : 'false'}" aria-label="Highlight X25519 public key bytes">X25519 split</button>
      <button data-inspector="mlkem" class="chip ${mClass}" aria-pressed="${mClass ? 'true' : 'false'}" aria-label="Highlight ML-KEM public key bytes">ML-KEM split</button>
    </div>`;

  if (keyOffset < 0) {
    return `${chips}<p>Unable to locate the key share in the serialized message.</p>`;
  }

  const groupOffset = keyOffset - 4; // 2-byte group + 2-byte length precede the key
  const x25519Start = keyOffset;
  const x25519End = keyOffset + X25519_BYTES;
  const mlkemStart = x25519End;
  const mlkemEnd = keyOffset + keyEx.length;

  const classify = (i: number): '' | 'group' | 'x25519' | 'mlkem' => {
    if (i >= groupOffset && i < groupOffset + 2) {
      return 'group';
    }
    if (i >= x25519Start && i < x25519End) {
      return 'x25519';
    }
    if (i >= mlkemStart && i < mlkemEnd) {
      return 'mlkem';
    }
    return '';
  };

  // Show framing + group + full X25519 + first 32 bytes of ML-KEM, then elide
  // the long random middle, then show the final 16 bytes of the message.
  const headEnd = Math.min(mlkemStart + 32, raw.length);
  const tailStart = Math.max(mlkemEnd - 16, headEnd);
  const elided = tailStart - headEnd;

  const head = renderHexDump(raw, 0, headEnd, classify, state.selectedInspector);
  const tail =
    tailStart < raw.length ? renderHexDump(raw, tailStart, raw.length, classify, state.selectedInspector) : '';
  const elision = elided > 0 ? `\n        ⋯ ${elided} bytes of ML-KEM-768 public key elided ⋯\n` : '\n';

  const captions: Record<string, string> = {
    group: `Named group X25519MLKEM768 (0x11EC) at byte 0x${offsetLabel(groupOffset)} — 2 bytes`,
    x25519: `X25519 public key at byte 0x${offsetLabel(x25519Start)} — ${X25519_BYTES} bytes`,
    mlkem: `ML-KEM-768 public key at byte 0x${offsetLabel(mlkemStart)} — ${mlkemEnd - mlkemStart} bytes`,
  };

  return `
    ${chips}
    <p class="wire-caption">${captions[state.selectedInspector]} · ClientHello total ${raw.length} bytes</p>
    <pre class="wire-block" aria-label="Real ClientHello wire bytes, hex dump with byte offsets">${head}${elision}${tail}</pre>
  `;
}

function stepNarrative(result: HandshakeResult): string {
  const shareGrowth = (result.clientHello.extensions.key_share.key_exchange.length / 32).toFixed(1);
  if (state.phaseStep === 1) {
    return `
      <p class="step-title">Step 1 of 3: the client generates two fresh keypairs</p>
      <p class="step-caption">One ${term('ephemeral', 'fresh per connection, then discarded — so a stolen long-term key cannot decrypt past sessions')} X25519 keypair (classical) and one ML-KEM-768 keypair (post-quantum). Their public halves are packed into a single <em>key share</em> the server will use to reach a shared secret.</p>
      <ul class="facts">
        <li><span class="dot dot-x25519" aria-hidden="true"></span>X25519 public key: ${preview(result.clientHello.extensions.key_share.key_exchange.subarray(0, 32))} (32 bytes)</li>
        <li><span class="dot dot-mlkem" aria-hidden="true"></span>ML-KEM-768 public key: ${preview(result.clientHello.extensions.key_share.key_exchange.subarray(32), 8, 8)} (1184 bytes)</li>
        <li>Combined key share: 1216 bytes (${shareGrowth}x larger than X25519 alone — almost all of it the ML-KEM key)</li>
      </ul>
    `;
  }
  if (state.phaseStep === 2) {
    return `
      <p class="step-title">Step 2 of 3: the client sends its ClientHello over the wire</p>
      <p class="step-caption">The combined key share travels inside one <em>${term('named group', 'a code that names which key-exchange algorithm both sides will use; here 0x11EC = X25519MLKEM768')}</em>, 0x11EC. The <em>Wire Format Inspector</em> below jumped to those exact bytes — that yellow 0x11EC is the whole handshake declaring "let's go hybrid".</p>
      <ul class="facts">
        <li>Named group: X25519MLKEM768 (0x11EC) — highlighted in the inspector</li>
        <li>Hybrid ClientHello: ${result.clientHello.rawBytes.length} bytes</li>
        <li>Classical (X25519-only) ClientHello would be: ${state.classical.clientHelloBytes} bytes</li>
      </ul>
    `;
  }
  const clientPrev = preview(result.hybridShared, 6, 6);
  const serverPrev = preview(result.serverHybridShared, 6, 6);
  return `
    <p class="step-title">Step 3 of 3: both sides independently reach the <em>same</em> 64-byte secret</p>
    <p class="step-caption">The server encapsulates to the client's ML-KEM key and runs X25519; the client decapsulates and runs X25519. Neither ever sent the secret — they each computed it. If even one primitive holds, an eavesdropper cannot.</p>
    <div class="secret-match">
      <div class="secret-side"><span class="secret-who">Client derives</span><code>${clientPrev}</code></div>
      <div class="secret-eq ${result.secretsAgree ? 'ok' : 'bad'}" aria-label="${result.secretsAgree ? 'secrets match' : 'secrets differ'}">${result.secretsAgree ? '✓ match' : '✗ differ'}</div>
      <div class="secret-side"><span class="secret-who">Server derives</span><code>${serverPrev}</code></div>
    </div>
    <ul class="facts">
      <li>Hybrid shared secret: ${result.hybridShared.length} bytes (32 X25519 + 32 ML-KEM)</li>
      <li>This 64-byte value feeds HKDF unchanged — see the pipeline below</li>
    </ul>
  `;
}

/**
 * HIGH-priority exhibit: draw the two 32-byte secrets (X25519 blue, ML-KEM
 * purple) concatenating into the 64-byte hybrid secret, which then flows as a
 * single arrow into HKDF-Extract, emitting the handshake secret and the two
 * traffic secrets. Every preview is the REAL value computed this run.
 */
function buildHybridSecretExhibit(result: HandshakeResult): string {
  const xHex = preview(result.x25519Component, 6, 6);
  const mHex = preview(result.mlkemComponent, 6, 6);
  const hybridHex = preview(result.hybridShared, 8, 8);
  const derivedHex = preview(result.derivedSecret, 6, 6);
  const hsHex = preview(result.handshakeSecret, 6, 6);
  const cHex = preview(result.clientHandshakeTrafficSecret, 6, 6);
  const sHex = preview(result.serverHandshakeTrafficSecret, 6, 6);

  return `
    <p>This is the step the whole handshake is named after. Two shared secrets — one
    from each primitive — are laid end to end (<code>||</code> means concatenate),
    and the joined 64-byte value is fed into the TLS 1.3 key schedule <strong>exactly
    where a single classical secret used to go</strong>. That substitution, and nothing
    else, is why TLS 1.3 needed <em>no protocol change</em> to go post-quantum.</p>

    <div class="hybrid-flow">
      <div class="hybrid-inputs">
        ${secretCapsule('x25519', 'X25519 secret', result.x25519Component.length, xHex)}
        <span class="concat-op" aria-hidden="true">||</span>
        ${secretCapsule('mlkem', 'ML-KEM-768 secret', result.mlkemComponent.length, mHex)}
      </div>

      <div class="flow-down" aria-hidden="true">
        <span class="flow-label">concatenate</span>
        <span class="flow-arrow">↓</span>
      </div>

      ${secretCapsule('hybrid', 'Hybrid shared secret (X25519 || ML-KEM)', result.hybridShared.length, hybridHex)}

      <div class="flow-down" aria-hidden="true">
        <span class="flow-label">fed as the (EC)DHE input</span>
        <span class="flow-arrow">↓</span>
      </div>

      <div class="hkdf-box">
        <span class="hkdf-title">${term('HKDF-Extract', 'the standard key-derivation step that mixes the shared secret into a uniform pseudorandom key')} · TLS 1.3 key schedule (RFC 8446 §7.1)</span>
        <div class="hkdf-stage"><span>salt = "derived" secret</span><code>${derivedHex}</code></div>
        <div class="hkdf-stage"><span>→ Handshake Secret</span><code>${hsHex}</code></div>
      </div>

      <div class="flow-down" aria-hidden="true">
        <span class="flow-label">HKDF-Expand-Label →</span>
        <span class="flow-arrow">↓</span>
      </div>

      <div class="traffic-out">
        <div class="capsule capsule-traffic"><span class="capsule-title">${term('client traffic secret', 'the key material the client side encrypts handshake records with')}</span><code class="capsule-hex">${cHex}</code></div>
        <div class="capsule capsule-traffic"><span class="capsule-title">${term('server traffic secret', 'the matching key material the server side encrypts with')}</span><code class="capsule-hex">${sHex}</code></div>
      </div>
    </div>
    <p class="metric-note">Every hex value above is the real secret derived in your browser this run — reload or press Reset and they all change together. The X25519 and ML-KEM halves are shown previewed (first and last bytes) so the concatenation is legible.</p>
  `;
}

/**
 * LOW-priority MTU visual: draw the 1216-byte hybrid key share against a typical
 * ~1500-byte Ethernet MTU, next to the tiny 32-byte classical share, so "the
 * cost is bytes" becomes spatial intuition. Widths are computed from the real
 * byte counts, capped at the MTU line.
 */
function buildMtuVisual(result: HandshakeResult): string {
  const MTU = 1500;
  const hybridBytes = result.clientHello.rawBytes.length;
  const classicalBytes = state.classical.clientHelloBytes;
  const pct = (n: number): number => Math.min(100, (n / MTU) * 100);
  return `
    <div class="mtu">
      <div class="mtu-track" aria-hidden="true">
        <div class="mtu-fill classical" style="width:${pct(classicalBytes).toFixed(1)}%"></div>
        <span class="mtu-bar-label">Classical ClientHello · ${classicalBytes} B</span>
      </div>
      <div class="mtu-track" aria-hidden="true">
        <div class="mtu-fill hybrid" style="width:${pct(hybridBytes).toFixed(1)}%"></div>
        <span class="mtu-bar-label">Hybrid ClientHello · ${hybridBytes} B</span>
      </div>
      <div class="mtu-boundary" aria-hidden="true"><span>~1500 B typical MTU</span></div>
    </div>
    <p class="metric-note">The classical hello is a sliver; the hybrid hello fills most of one <span class="nowrap">~1500-byte</span> packet. That is why the deployment risk is <strong>fragmentation</strong>, not compute — a hello that spans packet boundaries can trip middleboxes that mishandle fragmented handshakes.</p>
  `;
}

function render(): void {
  const r = state.result;
  const { classicalMs, hybridMs } = state.compute;
  // Signed percentage with a correct +/- prefix. Compute can occasionally
  // measure as a near-zero or slightly negative delta on a noisy sample, so the
  // sign must come from the value, not a hardcoded '+'.
  const signedPct = (numerator: number, denominator: number): string => {
    if (denominator <= 0) {
      return '0%';
    }
    const pct = (numerator / denominator) * 100;
    return `${pct >= 0 ? '+' : '−'}${Math.abs(pct).toFixed(0)}%`;
  };
  const computeOverhead = signedPct(hybridMs - classicalMs, classicalMs);
  const bytesOverhead = signedPct(r.totalBytes - state.classical.totalBytes, state.classical.totalBytes);

  appRoot.innerHTML = `
    <main class="shell" aria-label="Post-quantum TLS handshake simulation">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">X25519MLKEM768</h1>
          <p class="cl-hero-sub">Hybrid PQ key exchange · TLS 1.3 · X25519 + ML-KEM-768</p>
          <p class="cl-hero-desc">A browser simulation of the real hybrid handshake — watch the client combine an X25519 and an ML-KEM-768 key share on the wire and feed the concatenated secret into the TLS 1.3 key schedule.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">A harvest-now-decrypt-later attacker records today's TLS traffic to break it once a quantum computer exists. Hybrid key exchange keeps the session secret as long as either primitive holds, so the classical fallback covers any ML-KEM flaw and vice versa.</p>
        </aside>
      </header>

      <div class="hero-controls">
        <div class="controls">
          <button id="stepBtn" class="btn" aria-label="Advance to the next handshake step">Step</button>
          <button id="autoBtn" class="btn" aria-label="Toggle automatic step playback" aria-pressed="${state.autoPlay ? 'true' : 'false'}">${state.autoPlay ? 'Stop Auto-play' : 'Auto-play'}</button>
          <button id="resetBtn" class="btn" aria-label="Restart the handshake simulation">Reset</button>
          <label class="toggle"><input id="wireToggle" type="checkbox" aria-label="Show wire-format bytes" ${state.showWireBytes ? 'checked' : ''}/> Show wire bytes</label>
        </div>
      </div>

      <section class="exhibit intro" aria-label="Why hybrid post-quantum key exchange exists">
        <h3>Why does this exist?</h3>
        <p>Today's TLS uses <strong>X25519</strong>, a form of ${term('ECDH', 'elliptic-curve Diffie-Hellman: two sides derive a shared secret from public keys, secure because recovering the private key is computationally hard')}. A future quantum computer running <strong>${term("Shor's algorithm", "a quantum algorithm that factors integers and solves discrete logs efficiently — it breaks RSA and all elliptic-curve Diffie-Hellman, including X25519")}</strong> would break X25519 (and RSA, and every classical key exchange) outright. <strong>ML-KEM-768</strong> is a ${term('KEM', 'key encapsulation mechanism: instead of a shared computation, one side encapsulates a random secret to the other side’s public key. The PQ analog of encrypt-to-a-public-key.')} built on lattice problems that are <em>believed</em> to resist quantum attack.</p>
        <p><strong>Hybrid</strong> runs both and combines their secrets, so an attacker must break <em>both</em> to win — safe against a classical adversary today (X25519) <em>and</em> against a future quantum one (ML-KEM), with each covering any surprise weakness in the other. The threat table in Exhibit 2 reads that property straight off the rows.</p>
        <div class="glossary" aria-label="Key terms — hover or focus for definitions">
          ${term('key share', 'your public key, sent so the other side can derive a shared secret')}
          ${term('encapsulate', "a KEM's version of encrypt-to-a-public-key: produce a ciphertext plus a shared secret")}
          ${term('decapsulate', 'recover that shared secret from the ciphertext using your private key')}
          ${term('ephemeral', 'fresh per connection, discarded afterward')}
          ${term('codepoint', 'the numeric identifier (0x11EC) for this algorithm on the wire')}
        </div>
      </section>

      <section class="exhibit two-col">
        <article class="panel client">
          <h2>CLIENT</h2>
          <p>ClientHello key share: ${CLIENT_KEYSHARE_BYTES} bytes</p>
          <p>Group: 0x11EC</p>
          <p>Raw bytes: ${r.clientHello.rawBytes.length}</p>
        </article>
        <div class="wire-lane">
          <div class="arrow ${state.phaseStep >= 2 ? 'active' : ''}">ClientHello</div>
          <div class="arrow reverse ${state.phaseStep >= 3 ? 'active' : ''}">ServerHello</div>
        </div>
        <article class="panel server">
          <h2>SERVER</h2>
          <p>ServerHello key share: ${SERVER_KEYSHARE_BYTES} bytes</p>
          <p>Hybrid shared: ${r.hybridShared.length} bytes</p>
          <p>Raw bytes: ${r.serverHello.rawBytes.length}</p>
        </article>
      </section>

      <section class="exhibit narrative" aria-live="polite" aria-atomic="true">
        <h3>Exhibit 1: Full Handshake, Live</h3>
        ${stepNarrative(r)}
      </section>

      <section class="exhibit">
        <h3>Exhibit 2: Why Hybrid?</h3>
        <p>Final shared secret = X25519_secret || ML-KEM_secret. The connection survives if either primitive remains secure.</p>
        <table>
          <caption>Hybrid security outcomes by threat scenario</caption>
          <thead><tr><th scope="col">Threat</th><th scope="col">Connection</th></tr></thead>
          <tbody>
            <tr><td>Classical adversary, today</td><td class="ok">Secure</td></tr>
            <tr><td>Harvest-now-decrypt-later quantum threat</td><td class="ok">Secure</td></tr>
            <tr><td>Unexpected ML-KEM break</td><td class="ok">Secure via X25519</td></tr>
            <tr><td>Unexpected X25519 break</td><td class="ok">Secure via ML-KEM</td></tr>
            <tr><td>Both broken simultaneously</td><td class="bad">Broken</td></tr>
          </tbody>
        </table>
      </section>

      <section class="exhibit" aria-label="Building the hybrid secret">
        <h3>Exhibit 3: Building the Hybrid Secret</h3>
        ${buildHybridSecretExhibit(r)}
      </section>

      <section class="exhibit">
        <h3>Exhibit 4: Size and Compute Impact</h3>
        <div class="metrics">
          <div class="metric"><span>Client key share</span><strong>${CLIENT_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(CLIENT_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Server key share</span><strong>${SERVER_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(SERVER_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Total hello bytes</span><strong>${bytesOverhead}</strong><em>${r.totalBytes} vs ${state.classical.totalBytes} classical</em></div>
          <div class="metric"><span>Key-exchange compute</span><strong>${computeOverhead}</strong><em>${hybridMs.toFixed(3)}ms vs ${classicalMs.toFixed(3)}ms, measured</em></div>
        </div>
        <p class="metric-note">Compute is timed live in your browser (min of ${state.compute.samples} samples). The dominant real-world post-quantum cost is the extra ${r.totalBytes - state.classical.totalBytes} bytes on the wire, not these sub-millisecond computations.</p>
        ${buildMtuVisual(r)}
      </section>

      <section class="exhibit">
        <h3>Exhibit 5: Wire Format Inspector</h3>
        <p>The hex dump below is the real serialized ClientHello from this run — offsets and lengths are computed from the actual bytes.</p>
        ${state.showWireBytes ? createWireBytesBlock(r) : '<p>Enable "Show wire bytes" to inspect the 0x11EC key share framing.</p>'}
      </section>

      <section class="exhibit">
        <h3>Exhibit 6: Deployment Reality</h3>
        <p class="banner">As of mid-September 2025, about 43% of human-generated HTTPS traffic to Cloudflare already uses hybrid post-quantum key exchange.</p>
        <div class="grid2">
          <div>
            <h4>Browsers</h4>
            <p>Chrome M124 default, Firefox, Edge, Brave, Opera support this handshake family.</p>
          </div>
          <div>
            <h4>IETF and codepoint</h4>
            <p>draft-ietf-tls-ecdhe-mlkem-04, named group X25519MLKEM768 (0x11EC), replacing deprecated 0x6399.</p>
          </div>
        </div>
      </section>

      <section class="exhibit footnote">
        <p>Transcript hash (SHA-256 ClientHello||ServerHello): <code>${preview(r.transcriptHash, 12, 12)}</code></p>
      </section>
    </main>
<footer class="site-footer">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-wire/">hybrid-wire</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-guide/">hybrid-guide</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/">kyber-vault</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/">key-exchange</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-pq-rotation/">pq-rotation</a></div>
  <div class="site-footer-row"><a href="https://github.com/systemslibrarian/crypto-lab-pq-tls-handshake">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/">More crypto-lab demos</a></div>
  <div class="site-footer-verse">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
  `;

  const stepBtn = document.querySelector<HTMLButtonElement>('#stepBtn');
  const autoBtn = document.querySelector<HTMLButtonElement>('#autoBtn');
  const resetBtn = document.querySelector<HTMLButtonElement>('#resetBtn');
  const wireToggle = document.querySelector<HTMLInputElement>('#wireToggle');

  stepBtn?.addEventListener('click', () => {
    state.phaseStep = Math.min(3, state.phaseStep + 1);
    // MEDIUM: linking the step controls to the visuals. Reaching Step 2 (the
    // ClientHello being sent) reveals the wire dump and jumps it to the 0x11EC
    // named-group bytes, so "stepping" and the hex inspector are one story.
    if (state.phaseStep === 2) {
      state.showWireBytes = true;
      state.selectedInspector = 'group';
    }
    render();
  });

  autoBtn?.addEventListener('click', () => {
    state.autoPlay = !state.autoPlay;
    if (!state.autoPlay && state.autoTimer !== null) {
      window.clearInterval(state.autoTimer);
      state.autoTimer = null;
    }
    if (state.autoPlay) {
      state.autoTimer = window.setInterval(() => {
        state.phaseStep = Math.min(3, state.phaseStep + 1);
        if (state.phaseStep === 2) {
          state.showWireBytes = true;
          state.selectedInspector = 'group';
        }
        // Stop the moment we reach the final step — no dead extra tick that
        // would leave the button reading "Stop Auto-play" after playback ends.
        if (state.phaseStep >= 3) {
          state.autoPlay = false;
          if (state.autoTimer !== null) {
            window.clearInterval(state.autoTimer);
            state.autoTimer = null;
          }
        }
        render();
      }, 1200);
    }
    render();
  });

  resetBtn?.addEventListener('click', async () => {
    if (state.autoTimer !== null) {
      window.clearInterval(state.autoTimer);
      state.autoTimer = null;
    }
    state.autoPlay = false;
    await regenerateSimulation();
    render();
  });

  wireToggle?.addEventListener('change', () => {
    state.showWireBytes = Boolean(wireToggle.checked);
    render();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-inspector]').forEach((button) => {
    button.addEventListener('click', () => {
      const value = button.dataset.inspector;
      if (value === 'group' || value === 'x25519' || value === 'mlkem') {
        state.selectedInspector = value;
        render();
      }
    });
  });
}

async function warmupCheck(): Promise<void> {
  const x = x25519Keygen();
  const m = mlkem768Keygen();
  const client = buildClientKeyShare(x, m);
  const server = serverRespondToKeyShare(client.keyShare);
  const recovered = clientComputeHybridSecret(server.serverKeyShare, x, m);
  if (recovered.hybridShared.length !== 64) {
    throw new Error('Hybrid warmup failed');
  }

  const hello = await buildClientHello();
  const serverHello = await buildServerHello(hello.clientHello);
  if (hello.clientHello.extensions.key_share.group !== TLS_CONSTANTS.GROUP_X25519MLKEM768) {
    throw new Error('Expected X25519MLKEM768 group in ClientHello');
  }
  if (serverHello.serverHello.extensions.key_share.key_exchange.length !== SERVER_KEYSHARE_BYTES) {
    throw new Error('Server key share size mismatch');
  }
}

await warmupCheck();
render();
