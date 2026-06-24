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
      <p class="step-title">Step 1/3: client generates ephemeral keypairs</p>
      <ul class="facts">
        <li>X25519 public: ${preview(result.clientHello.extensions.key_share.key_exchange.subarray(0, 32))} (32 bytes)</li>
        <li>ML-KEM-768 public: ${preview(result.clientHello.extensions.key_share.key_exchange.subarray(32), 8, 8)} (1184 bytes)</li>
        <li>Hybrid key share payload: 1216 bytes (${shareGrowth} larger than X25519-only)</li>
      </ul>
    `;
  }
  if (state.phaseStep === 2) {
    return `
      <p class="step-title">Step 2/3: client sends ClientHello</p>
      <ul class="facts">
        <li>Named group: X25519MLKEM768 (0x11EC)</li>
        <li>ClientHello bytes: ${result.clientHello.rawBytes.length}</li>
        <li>Classical ClientHello bytes: ${state.classical.clientHelloBytes}</li>
      </ul>
    `;
  }
  return `
    <p class="step-title">Step 3/3: server responds and client derives the same hybrid secret</p>
    <ul class="facts">
      <li>ServerHello key share: 1120 bytes (32 + 1088)</li>
      <li>Hybrid shared secret: ${result.hybridShared.length} bytes</li>
      <li>Client/server traffic secrets: ${result.clientHandshakeTrafficSecret.length} bytes each</li>
    </ul>
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
      <header class="hero">
        <p class="kicker">Post-Quantum TLS 1.3 Handshake Lab</p>
        <h1>X25519MLKEM768 on the Wire</h1>
        <p class="subtitle">A browser simulation of the real hybrid handshake now used by Chrome, Cloudflare, and Google Search.</p>
        <div class="controls">
          <button id="stepBtn" class="btn" aria-label="Advance to the next handshake step">Step</button>
          <button id="autoBtn" class="btn" aria-label="Toggle automatic step playback" aria-pressed="${state.autoPlay ? 'true' : 'false'}">${state.autoPlay ? 'Stop Auto-play' : 'Auto-play'}</button>
          <button id="resetBtn" class="btn" aria-label="Restart the handshake simulation">Reset</button>
          <label class="toggle"><input id="wireToggle" type="checkbox" aria-label="Show wire-format bytes" ${state.showWireBytes ? 'checked' : ''}/> Show wire bytes</label>
        </div>
      </header>

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

      <section class="exhibit">
        <h3>Exhibit 3: Size and Compute Impact</h3>
        <div class="metrics">
          <div class="metric"><span>Client key share</span><strong>${CLIENT_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(CLIENT_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Server key share</span><strong>${SERVER_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(SERVER_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Total hello bytes</span><strong>${bytesOverhead}</strong><em>${r.totalBytes} vs ${state.classical.totalBytes} classical</em></div>
          <div class="metric"><span>Key-exchange compute</span><strong>${computeOverhead}</strong><em>${hybridMs.toFixed(3)}ms vs ${classicalMs.toFixed(3)}ms, measured</em></div>
        </div>
        <p class="metric-note">Compute is timed live in your browser (min of ${state.compute.samples} samples). The dominant real-world post-quantum cost is the extra ${r.totalBytes - state.classical.totalBytes} bytes on the wire, not these sub-millisecond computations.</p>
      </section>

      <section class="exhibit">
        <h3>Exhibit 4: Wire Format Inspector</h3>
        <p>The hex dump below is the real serialized ClientHello from this run — offsets and lengths are computed from the actual bytes.</p>
        ${state.showWireBytes ? createWireBytesBlock(r) : '<p>Enable "Show wire bytes" to inspect the 0x11EC key share framing.</p>'}
      </section>

      <section class="exhibit">
        <h3>Exhibit 5: Deployment Reality</h3>
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
  `;

  const stepBtn = document.querySelector<HTMLButtonElement>('#stepBtn');
  const autoBtn = document.querySelector<HTMLButtonElement>('#autoBtn');
  const resetBtn = document.querySelector<HTMLButtonElement>('#resetBtn');
  const wireToggle = document.querySelector<HTMLInputElement>('#wireToggle');

  stepBtn?.addEventListener('click', () => {
    state.phaseStep = Math.min(3, state.phaseStep + 1);
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
