import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, which is
 * step 1 of 3 with both wire arrows inactive and the hex dump absent from the
 * DOM entirely; the shared skip link focused; a glossary term focused, which is
 * the only state its focus ring is ever painted in; the wire dump enabled by its
 * own toggle and each of the three inspector chips in turn, each of which
 * repaints the dump with a different span highlighted; the dump toggled back
 * off; all three handshake steps, including the step-2 coupling that forces the
 * dump on and jumps the inspector to the 0x11EC group bytes, and the clamp at
 * step 3; Reset, which regenerates the whole handshake from a fresh ML-KEM-768
 * keygen; and auto-play both stopping ITSELF at step 3 and being stopped by
 * hand. Every one of those states is scanned, in both themes, at desktop and
 * phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (`.shell` animates
 * from `opacity: 0` and `.arrow.active` runs an infinite pulse, both of which
 * the stylesheet's own reduced-motion block clamps rather than cancels), why no
 * `revealAll()` runs on a page with no disclosures, why the lab's defaults are
 * asserted rather than assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
