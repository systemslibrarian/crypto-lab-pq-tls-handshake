import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces (`e2e/a11y.spec.ts` as it stood before this commit):
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `killMotion()` pushed
 *     `animation-duration: 0s !important`, `transition-duration: 0s !important`
 *     and `scroll-behavior: auto !important` through `addStyleTag` into every
 *     element and pseudo-element, and it was called TWICE per test. That
 *     BYPASSED this stylesheet's own `@media (prefers-reduced-motion: reduce)`
 *     block instead of exercising it. The injection also could not be checked
 *     against the block it was standing in for: `.arrow.active` runs
 *     `pulse 1000ms ease infinite`, which animates `transform: translateX` and a
 *     `box-shadow` — the stylesheet's block clamps its duration to 0.01ms and
 *     caps the iteration count at 1, and the difference between "clamped" and
 *     "zeroed" is exactly where a fill-mode strands an element invisible. It
 *     does not here (neither `pulse` nor `fade-in` has a fill mode, and both end
 *     at their declared values), and `expectNotBlank` is what turns that reading
 *     into a measurement in every driven state.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `revealAll()` set `open = true` on every
 *     `<details>` and stripped `hidden` from every element carrying it — on a
 *     page whose own docblock admitted "There are no <details> here", so the
 *     helper existed purely to hide the fact that it could not have worked.
 *     This gate touches neither.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE. `driveDemo()`
 *     enabled the wire dump, clicked all three inspector chips in turn, and
 *     stepped the handshake twice — then `scan()` ran a single time, so the
 *     group and X25519 highlight states, and both intermediate handshake steps,
 *     had been overwritten before anything measured them. Auto-play and Reset
 *     were never driven at all. Nothing ever ran at phone width. This drive
 *     scans after every single step, in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: almost every
 *     surface here is an `rgba()` or a `color-mix()` over a three-layer gradient
 *     body, which axe declines to resolve and files under `incomplete`; and
 *     `aria-prohibited-attr`, where an `aria-label` on a role-less element
 *     lands, is `incomplete`-only too — which matters, because this page puts
 *     `aria-label` on a `<pre>`, on two plain `<div>`s and on a `<section>`.
 *
 *  5. IT HAD NO CONTRAST, REFLOW, KEYBOARD-SCROLLER OR NON-TEXT ORACLE. This
 *     page needs all four: `.wire-block` is a 280px-capped `overflow: auto`
 *     scroller holding a hex dump with no focusable content in it, `.two-col` is
 *     a `1fr 220px 1fr` grid, and `.arrow` ships at `opacity: 0.35` with real
 *     words in it.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page has the ingredients and not the defect, and the check is what makes
 * that a measurement. `.shell` — which wraps the entire document — runs
 * `fade-in 500ms ease` from `opacity: 0`, and the reduced-motion block clamps
 * the duration to 0.01ms rather than cancelling the animation. Because
 * `fade-in` declares no `animation-fill-mode`, the 0 is neither held before nor
 * after, so the shell settles at its declared `opacity: 1` almost immediately.
 * Add a `both` to that keyframe rule and the whole page would render blank for
 * every reader with the preference set; this assertion is what would catch it.
 *
 * `aria-hidden` subtrees are excluded. On this page the hidden set is nine
 * elements, enumerated in the header of `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created.
 *
 * This page is unusual in that its module body uses TOP-LEVEL AWAIT — it awaits
 * a full ML-KEM-768 keygen, a real handshake and a warm-up self-check before it
 * renders anything at all. If any of that throws, `#app` stays empty and there
 * is nothing on screen for a DOM assertion to be wrong about; only the error
 * stream says so. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page declares no banner of its own — its hero is a `<header
 * class="cl-hero">` INSIDE `<main class="shell">`, which scopes it out of the
 * banner role by nesting, and `index.html`'s `dedupeBanner()` skips it for the
 * same reason. Asserting the OUTCOME rather than either mechanism means a
 * change to the nesting is caught too.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the shared bar's toggle
 * writes `localStorage.setItem('theme', …)`. If those keys drift apart the
 * theme silently stops persisting, and this boot fails on `data-theme` rather
 * than quietly scanning dark twice — which is what the gate this replaces did
 * for its first test, since it never seeded a theme at all and only asserted
 * the attribute it happened to find.
 *
 * The defaults are asserted at length because the arrival state of this page is
 * a PARTIAL one that the old drive stepped straight past: the simulation ships
 * at `phaseStep = 1`, so both wire arrows are inactive and rendered at
 * `opacity: 0.35`; the wire dump is OFF, so Exhibit 5 shows a prompt instead of
 * a hex dump; and auto-play is off. Every one of those is a real rendering, it
 * is the first one every reader sees, and none of them had ever been scanned.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // `src/main.ts` uses top-level await around a real ML-KEM-768 keygen and a
  // warm-up self-check, so `#app` is empty until all of that resolves. A
  // navigation that resolves proves nothing.
  await expect(page.locator('#app main.shell')).toBeVisible();
  await expect(page.locator('section.exhibit')).toHaveCount(9);
  await assertSingleBanner(page);

  // The reduced-motion block's effect, asserted rather than assumed: the shell
  // is opaque, not held at the `fade-in` keyframe's starting `opacity: 0`.
  expect(
    await page.evaluate(() => getComputedStyle(document.querySelector('.shell')!).opacity),
    'reduced motion must leave the shell opaque, not stranded at fade-in from opacity 0'
  ).toBe('1');

  // ── The arrival state: step 1 of 3, wire dump off, auto-play off ─────────
  await expect(page.locator('.step-title')).toHaveText(/Step 1 of 3/);
  await expect(page.locator('.arrow.active')).toHaveCount(0);
  await expect(page.locator('#wireToggle')).not.toBeChecked();
  await expect(page.locator('.wire-block')).toHaveCount(0);
  await expect(page.locator('[data-inspector]')).toHaveCount(0);
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#autoBtn')).toHaveText('Auto-play');

  // The handshake really ran: both key shares and the transcript hash are real
  // values computed in the browser, not placeholders.
  await expect(page.locator('.panel.client')).toContainText('1216 bytes');
  await expect(page.locator('.panel.server')).toContainText('1120 bytes');
  await expect(page.locator('.footnote code')).not.toBeEmpty();
  await expect(page.locator('.capsule-hybrid .capsule-hex')).not.toBeEmpty();
  // …and the side-by-side secret comparison does NOT exist yet: `stepNarrative`
  // renders `.secret-match` only at step 3, so the exhibit that proves both
  // sides derived the same value is absent from the arrival state entirely.
  await expect(page.locator('.secret-match')).toHaveCount(0);

  // This lab has no disclosures at all — the gate it replaces shipped a
  // `revealAll()` that opened `<details>` on a page with none.
  await expect(page.locator('details')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the old gate
 * never ran at a narrow viewport, so nothing here had ever been reflowed. The
 * shapes that break it on this page are `.two-col` (`1fr 220px 1fr`),
 * `.metrics` (`repeat(4, minmax(0, 1fr))`), the `.hybrid-inputs` capsule row
 * whose members are `min-width: 12rem`, the `.secret-match` row, and above all
 * the `.wire-block` hex dump, whose lines are fixed-width and cannot wrap.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element, and the
    // hex dump inside `.wire-block` is exactly that decoy.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * `.wire-block` is the case this exists for: a `<pre>` under a 280px
 * `overflow: auto` cap holding a multi-hundred-byte hex dump with no focusable
 * content anywhere inside it. It is also a check that only bites in a state a
 * drive has to build — the block does not exist in the DOM at all until the
 * wire toggle is checked or the handshake is stepped to 2.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * The gate this replaces had no such check at all. It is needed here because
 * every control on the page — the three `.btn`s and the three inspector
 * `.chip`s — draws itself the same way: a hardcoded `#172235` fill (re-skinned
 * to `#eef3fa` in the light theme) with a `1px solid var(--line)` edge, where
 * `--line` is the SURFACE divider also used for exhibit, panel, table-row,
 * capsule and glossary edges.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it, or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill.
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components; nothing on this
 *    page currently ships disabled, and the exclusion is here so that adding one
 *    does not silently start failing the gate for a reason WCAG does not ask
 *    about.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a copy — and its measurement is recorded in
 *    `nontext-baseline.ts` and reported upward rather than patched in one repo,
 *    so the exclusion is a decision and not an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `rgba()` over gradients and `color-mix()`, which `getComputedStyle`
    // reports unchanged and which a regex reads as null — landing the walk on
    // the wrong backdrop.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>('button, select, textarea, input')
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') return;
        // A native checkbox paints itself from UA pseudo-elements that
        // `getComputedStyle` on the host cannot see, so its `background` and
        // `border` are not what a reader looks at. Judging it here would be
        // measuring something the page does not draw.
        if ((el as HTMLInputElement).type === 'checkbox') return;
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * The wrapper is deliberately shaped so the real call cannot end up on the wrong
 * side of a `COLLECTING` guard: fleet-wide, `expectNoNewNonTextFailures` was
 * reachable only from inside `expectScrollersReachableSoft`, AFTER that
 * function's `if (!COLLECTING) return …`, so in a strict run — which is every
 * run in CI and every run anyone reads as a pass — `nontext.ts` never executed
 * at all. It is called from `scan()` here, at every driven state.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both are live on this page — the `< `/` >` direction markers on the two
 * wire arrows are generated content and are the only thing saying which way each
 * message travels.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since every
 *    surface on this page is an `rgba()` or a `color-mix()` over a three-layer
 *    gradient body. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label` on a role-less element hides, a defect that never reaches the
 *    violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11, which axe has no
 *    rule for; see `auditControlBoundaries`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass; thirteen repos in this fleet had shipped that
  // form. Running the two sets separately and merging is the only way to have
  // both. The landmark four are wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch: a shared sticky `<header role="banner">` above a
  // `<main class="shell">` containing a `<header class="cl-hero">` with an
  // `<aside role="complementary">` inside it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Drive the lab through every state it can render, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS PARTIAL, AND IT IS SCANNED FIRST. The simulation
 *    ships at step 1 of 3, both wire arrows inactive at `opacity: 0.35`, the
 *    wire dump absent from the DOM entirely. That is what every reader meets,
 *    and the old drive stepped past it before its only scan.
 *
 *  - EVERY STEP, SEPARATELY. The three handshake steps render three completely
 *    different narratives and progressively activate the two wire arrows, and
 *    step 2 additionally FORCES the wire dump on and jumps the inspector to the
 *    group bytes. The old drive stepped twice and measured only the end.
 *
 *  - EVERY BRANCH OF THE INSPECTOR. Each of the three chips repaints the hex
 *    dump with a different span highlighted and rewrites the caption; the
 *    highlight classes (`.group.active`, `.x25519.active`, `.mlkem.active`)
 *    each paint an `rgba()` tint and an ink that no other state shows. The old
 *    drive clicked all three and then scanned once, so two of the three were
 *    thrown away.
 *
 *  - THE TOGGLE IN BOTH DIRECTIONS. Unchecking `#wireToggle` after step 2 is
 *    the only route back to the "Enable Show wire bytes to inspect…" prompt
 *    once the dump has appeared, and it is reachable by a reader in one click.
 *
 *  - AUTO-PLAY AND RESET, WHICH WERE NEVER DRIVEN. Auto-play flips `#autoBtn`
 *    to `aria-pressed="true"` and relabels it, then STOPS ITSELF on reaching
 *    step 3 — a self-clearing pressed state worth measuring at both ends.
 *    Reset regenerates the whole simulation asynchronously (a fresh ML-KEM
 *    keygen and handshake) and returns to step 1.
 *
 *  - NO FIXED TIMEOUTS. Every action has a rendered consequence — a step title,
 *    an `aria-pressed` value, the wire block's presence, a chip's `active`
 *    class — and the drive waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, step 1 of 3, wire dump off, both arrows inactive');

  // The shared skip link is revealed only by a keyboard Tab (it lives at
  // `top: -3rem` until focused), and it is the first focusable thing on the page.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused');
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());

  // A glossary term focused: `.term` is `tabindex="0"` and gets a `--wire`
  // focus ring, which is the only state that ring is ever painted in.
  await page.locator('.glossary .term').first().focus();
  await expect(page.locator('.glossary .term').first()).toBeFocused();
  await scanAt('glossary term focused');
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());

  // ── The wire dump, reached by the toggle rather than by stepping ──────────
  await page.locator('#wireToggle').check();
  await expect(page.locator('.wire-block')).toBeVisible();
  await expect(page.locator('[data-inspector]')).toHaveCount(3);
  await scanAt('wire dump enabled at step 1, group bytes highlighted');

  for (const which of ['x25519', 'mlkem', 'group'] as const) {
    await page.locator(`[data-inspector="${which}"]`).click();
    await expect(page.locator(`[data-inspector="${which}"]`)).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    await expect(page.locator(`.wire-block .${which}.active`).first()).toBeVisible();
    await scanAt(`wire inspector highlighting ${which}`);
  }

  await page.locator('#wireToggle').uncheck();
  await expect(page.locator('.wire-block')).toHaveCount(0);
  await scanAt('wire dump toggled back off');

  // ── The three handshake steps ─────────────────────────────────────────────
  // Step 2 forces the dump back on and jumps the inspector to the group bytes;
  // that coupling is a rendering no other route produces.
  await page.locator('#stepBtn').click();
  await expect(page.locator('.step-title')).toHaveText(/Step 2 of 3/);
  await expect(page.locator('.arrow.active')).toHaveCount(1);
  await expect(page.locator('#wireToggle')).toBeChecked();
  await expect(page.locator('[data-inspector="group"]')).toHaveAttribute('aria-pressed', 'true');
  await scanAt('step 2 of 3 — ClientHello on the wire, dump auto-revealed');

  await page.locator('#stepBtn').click();
  await expect(page.locator('.step-title')).toHaveText(/Step 3 of 3/);
  await expect(page.locator('.arrow.active')).toHaveCount(2);
  await expect(page.locator('.secret-match .secret-eq')).toHaveText('✓ match');
  await scanAt('step 3 of 3 — both sides derive the same secret, both arrows active');

  // Step clamps at 3; pressing again is a real thing a reader does and must not
  // change the rendering.
  await page.locator('#stepBtn').click();
  await expect(page.locator('.step-title')).toHaveText(/Step 3 of 3/);
  await scanAt('step pressed past the end, clamped at 3');

  // ── Auto-play, which the old gate never touched ───────────────────────────
  await page.locator('#resetBtn').click();
  await expect(page.locator('.step-title')).toHaveText(/Step 1 of 3/);
  await expect(page.locator('.arrow.active')).toHaveCount(0);
  // Reset does NOT un-check the wire toggle, and that is asserted rather than
  // assumed because the assumption was wrong the first time this drive ran.
  // `regenerateSimulation()` resets `phaseStep` and re-runs the handshake but
  // deliberately leaves `showWireBytes` alone — the toggle is a reader's
  // display preference, not part of the simulation — so this is a real state
  // the reader reaches in one click: step 1 of 3 with a freshly generated
  // ClientHello already open in the inspector. Its bytes have all changed.
  await expect(page.locator('#wireToggle')).toBeChecked();
  await expect(page.locator('.wire-block')).toBeVisible();
  await scanAt('reset — fresh handshake regenerated, back to step 1, dump still open');

  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#autoBtn')).toHaveText('Stop Auto-play');
  await scanAt('auto-play running');

  // Auto-play stops ITSELF at step 3 and clears its own pressed state. Waiting
  // on that (rather than on a timeout) is what makes the assertion meaningful.
  await expect(page.locator('.step-title')).toHaveText(/Step 3 of 3/, { timeout: 30_000 });
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#autoBtn')).toHaveText('Auto-play');
  await scanAt('auto-play reached step 3 and stopped itself');

  // Stopping auto-play by hand is a different path through the same handler.
  await page.locator('#resetBtn').click();
  await expect(page.locator('.step-title')).toHaveText(/Step 1 of 3/);
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');
  await scanAt('auto-play stopped by hand before reaching the end');
}
