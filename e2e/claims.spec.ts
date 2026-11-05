import { expect, test } from '@playwright/test';

test('the skip link targets and focuses the rendered main content', async ({ page }) => {
  await page.goto('.');
  const skip = page.getByRole('link', { name: 'Skip to content' });
  await expect(skip).toHaveAttribute('href', '#main-content');
  await skip.focus();
  await skip.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
});

test('the page scopes its claims to TLS key exchange', async ({ page }) => {
  await page.goto('.');
  const body = page.locator('body');
  await expect(body).toContainText('hybrid key-exchange portion of TLS 1.3');
  await expect(page.getByRole('heading', { name: 'Exhibit 1: Hybrid Key Exchange, Live' })).toBeVisible();
  await expect(body).not.toContainText('Full Handshake');
  await expect(body).not.toContainText('no protocol change');
  await expect(body).toContainText('key schedule itself needs no redesign');
});

test('visible control text remains in every accessible name', async ({ page }) => {
  await page.goto('.');
  await page.locator('#wireToggle').check();

  /**
   * WCAG 2.5.3 Label in Name: the accessible name must CONTAIN the visible
   * label, not equal it. This asserted equality when it was written, which
   * matched this branch's markup — then main's 4d12e09 gave each control a
   * descriptive `aria-label` ("Reset: restart the handshake simulation"), which
   * is both more useful to a screen-reader user and still conformant. Equality
   * would have forced those labels back out to keep a test green.
   *
   * Derived from the page rather than from a list, so a control added later is
   * covered without anyone remembering to add it here.
   */
  const controls = await page.locator('button, input[type="checkbox"]').evaluateAll((nodes) =>
    nodes
      .filter((node) => (node as HTMLElement).offsetParent !== null)
      .map((node) => {
        // A checkbox's visible label is the text of the <label> wrapping it.
        const visibleSource = node.tagName === 'INPUT' ? node.closest('label') : node;
        return {
          visible: (visibleSource?.textContent ?? '').replace(/\s+/g, ' ').trim(),
          accessible: (node.getAttribute('aria-label') ?? visibleSource?.textContent ?? '').replace(/\s+/g, ' ').trim(),
        };
      })
      .filter((control) => control.visible.length > 0),
  );

  // A scan that found nothing would pass the rule below over nothing.
  expect(controls.length).toBeGreaterThanOrEqual(6);
  // Case-insensitive: WCAG 2.5.3 exists so a voice-control user can say the
  // visible label, and voice input normalises case. "Advance to the next
  // handshake step" does contain "Step" for that purpose.
  const offenders = controls.filter(
    (control) => !control.accessible.toLowerCase().includes(control.visible.toLowerCase()),
  );
  expect(offenders, `accessible names that drop their visible label: ${JSON.stringify(offenders)}`).toEqual([]);

  // The controls this test was written for are among them.
  const visibleLabels = controls.map((control) => control.visible);
  for (const label of ['Step', 'Reset', '0x11EC group', 'X25519 split', 'ML-KEM split']) {
    expect(visibleLabels, label).toContain(label);
  }
});

/**
 * The page's own README warns that for X25519MLKEM768 the ML-KEM share comes
 * FIRST, and that an implementation concatenating in name order will not
 * interoperate. hybrid.ts gets this right — concatBytes(mlkem, x25519) — but
 * two pieces of rendered copy stated the reverse, teaching exactly the interop
 * trap the lab exists to warn about. These pin the displayed order, and the
 * displayed bytes, to the order the code actually uses.
 */

test('the rendered hybrid order matches RFC 10024’s ML-KEM-first order', async ({
  page,
}) => {
  await page.goto('.');
  await expect(page.locator('.cl-topbar')).toBeVisible();

  const body = page.locator('body');
  await expect(body).toContainText('ML-KEM_secret || X25519_secret');
  await expect(body).not.toContainText('X25519_secret || ML-KEM_secret');

  await page.locator('#stepBtn').click();
  await page.locator('#stepBtn').click();

  await expect(body).toContainText('32 ML-KEM + 32 X25519');
  await expect(body).not.toContainText('32 X25519 + 32 ML-KEM');
  await expect(page.getByRole('link', { name: 'RFC 10024' })).toHaveAttribute('href', 'https://www.rfc-editor.org/rfc/rfc10024.html');
  await expect(body).toContainText('final IETF Standards Track');
});

test('the displayed hybrid secret really begins with the ML-KEM component', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('.cl-topbar')).toBeVisible();
  await page.locator('#stepBtn').click();
  await page.locator('#stepBtn').click();

  // Each capsule shows a head…tail preview of the real value derived this run.
  const hexOf = async (kind: string): Promise<string> =>
    ((await page.locator(`.capsule-${kind} .capsule-hex`).first().textContent()) ?? '').trim();

  const mlkem = await hexOf('mlkem');
  const x25519 = await hexOf('x25519');
  const hybrid = await hexOf('hybrid');
  for (const [name, value] of [
    ['ml-kem', mlkem],
    ['x25519', x25519],
    ['hybrid', hybrid],
  ] as const) {
    expect(value, `${name} capsule rendered no hex`).not.toBe('');
  }

  // Compare leading bytes: the hybrid value must start with the ML-KEM
  // component's bytes, not X25519's. Previews are "aabb…ccdd" style, so take
  // the hex before the ellipsis and compare the shorter common prefix.
  const head = (s: string): string => (s.split(/[….]/)[0] ?? '').replace(/\s/g, '');
  const tail = (s: string): string => {
    const parts = s.split(/[….]+/);
    return (parts[parts.length - 1] ?? '').replace(/\s/g, '');
  };

  const n = Math.min(head(hybrid).length, head(mlkem).length);
  expect(n, 'no comparable prefix in the previews').toBeGreaterThan(0);
  expect(head(hybrid).slice(0, n)).toBe(head(mlkem).slice(0, n));
  // And it must NOT start with the X25519 component (the reversed order).
  expect(head(hybrid).slice(0, n)).not.toBe(head(x25519).slice(0, n));

  const t = Math.min(tail(hybrid).length, tail(x25519).length);
  expect(t, 'no comparable suffix in the previews').toBeGreaterThan(0);
  expect(tail(hybrid).slice(-t)).toBe(tail(x25519).slice(-t));
});
