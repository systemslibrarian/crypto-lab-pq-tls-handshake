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
  showWireBytes: false,
  autoPlay: false,
  autoTimer: null,
  selectedInspector: 'group',
};

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function spacedHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(' ');
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
  state.phaseStep = 1;
}

function createWireBytesBlock(result: HandshakeResult): string {
  const keyShare = result.clientHello.extensions.key_share.key_exchange;
  const groupHex = '11 ec';
  const xHex = spacedHex(keyShare.subarray(0, X25519_BYTES));
  const mHex = spacedHex(keyShare.subarray(X25519_BYTES));

  const groupClass = state.selectedInspector === 'group' ? 'active' : '';
  const xClass = state.selectedInspector === 'x25519' ? 'active' : '';
  const mClass = state.selectedInspector === 'mlkem' ? 'active' : '';

  return `
    <div class="inspector-toggle">
      <button data-inspector="group" class="chip ${groupClass}">Highlight 0x11EC</button>
      <button data-inspector="x25519" class="chip ${xClass}">Highlight X25519 split</button>
      <button data-inspector="mlkem" class="chip ${mClass}">Highlight ML-KEM split</button>
    </div>
    <pre class="wire-block">
16 03 01 05 03 01 00 04 ff 03 03 ...
00 2b 00 03 02 03 04
00 0a 00 06 00 04 11 ec 00 1d
00 33 04 c6
  <span class="group ${groupClass}">${groupHex}</span> 04 c0
  <span class="x25519 ${xClass}">${xHex}</span>
  <span class="mlkem ${mClass}">${mHex}</span>
    </pre>
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
  const latencyIncrease = (((r.latencyMs - state.classical.latencyMs) / state.classical.latencyMs) * 100).toFixed(2);

  appRoot.innerHTML = `
    <main class="shell">
      <header class="hero">
        <p class="kicker">Post-Quantum TLS 1.3 Handshake Lab</p>
        <h1>X25519MLKEM768 on the Wire</h1>
        <p class="subtitle">A browser simulation of the real hybrid handshake now used by Chrome, Cloudflare, and Google Search.</p>
        <div class="controls">
          <button id="stepBtn" class="btn">Step</button>
          <button id="autoBtn" class="btn">${state.autoPlay ? 'Stop Auto-play' : 'Auto-play'}</button>
          <button id="resetBtn" class="btn">Reset</button>
          <label class="toggle"><input id="wireToggle" type="checkbox" ${state.showWireBytes ? 'checked' : ''}/> Show wire bytes</label>
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

      <section class="exhibit narrative">
        <h3>Exhibit 1: Full Handshake, Live</h3>
        ${stepNarrative(r)}
      </section>

      <section class="exhibit">
        <h3>Exhibit 2: Why Hybrid?</h3>
        <p>Final shared secret = X25519_secret || ML-KEM_secret. The connection survives if either primitive remains secure.</p>
        <table>
          <thead><tr><th>Threat</th><th>Connection</th></tr></thead>
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
        <h3>Exhibit 3: Size and Latency Impact</h3>
        <div class="metrics">
          <div class="metric"><span>Client key share</span><strong>${CLIENT_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(CLIENT_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Server key share</span><strong>${SERVER_KEYSHARE_BYTES} bytes</strong><em>${bytesMultiplier(SERVER_KEYSHARE_BYTES)}</em></div>
          <div class="metric"><span>Total hello bytes</span><strong>${r.totalBytes}</strong><em>vs ${state.classical.totalBytes} classical</em></div>
          <div class="metric"><span>Latency increase</span><strong>${latencyIncrease}%</strong><em>${r.latencyMs.toFixed(2)}ms vs ${state.classical.latencyMs.toFixed(2)}ms</em></div>
        </div>
      </section>

      <section class="exhibit">
        <h3>Exhibit 4: Wire Format Inspector</h3>
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
        state.phaseStep += 1;
        if (state.phaseStep > 3) {
          state.phaseStep = 3;
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
