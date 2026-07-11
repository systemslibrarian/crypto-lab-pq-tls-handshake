import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the PQ TLS handshake lab.
 *
 * Scans the full page in BOTH themes with the live simulation DRIVEN so every
 * dynamically-injected region is present when axe runs: the wire-byte hex dump
 * is enabled and each inspector chip (group / X25519 / ML-KEM) is exercised,
 * and the handshake is stepped to its final state. There are no <details> here
 * (the app is a single scrolling page rendered by main.ts), but we still
 * generically expand any collapsibles for robustness.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states can't hide text
// from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      scroll-behavior:auto!important;
    }`,
  });
}

// Force-reveal any class-toggled / [hidden] / display:none collapsibles.
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive the live simulation so injected output regions exist during the scan.
async function driveDemo(page: Page): Promise<void> {
  // Reveal the wire-byte hex dump (Exhibit 4).
  const wireToggle = page.locator('#wireToggle');
  if (!(await wireToggle.isChecked())) {
    await wireToggle.check();
  }
  await expect(page.locator('.wire-block')).toBeVisible();

  // Exercise every inspector chip so each highlight class is rendered.
  for (const which of ['x25519', 'mlkem', 'group']) {
    await page.locator(`[data-inspector="${which}"]`).click();
  }

  // Step the handshake to its final state (three steps).
  await page.locator('#stepBtn').click();
  await page.locator('#stepBtn').click();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // App is rendered by main.ts; wait for the shared header toggle + first control.
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#stepBtn')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (simulation driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemo(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (simulation driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemo(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
