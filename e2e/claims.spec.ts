import { expect, test } from '@playwright/test';

/**
 * The page's own README warns that for X25519MLKEM768 the ML-KEM share comes
 * FIRST, and that an implementation concatenating in name order will not
 * interoperate. hybrid.ts gets this right — concatBytes(mlkem, x25519) — but
 * two pieces of rendered copy stated the reverse, teaching exactly the interop
 * trap the lab exists to warn about. These pin the displayed order, and the
 * displayed bytes, to the order the code actually uses.
 */

test('the rendered hybrid order matches the draft-mandated ML-KEM-first order', async ({
  page,
}) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();

  const body = page.locator('body');
  await expect(body).toContainText('ML-KEM_secret || X25519_secret');
  await expect(body).not.toContainText('X25519_secret || ML-KEM_secret');

  await page.locator('#stepBtn').click();
  await page.locator('#stepBtn').click();

  await expect(body).toContainText('32 ML-KEM + 32 X25519');
  await expect(body).not.toContainText('32 X25519 + 32 ML-KEM');
});

test('the displayed hybrid secret really begins with the ML-KEM component', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
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
