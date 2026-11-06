import { expect, test } from '@playwright/test';
test('confidentiality and local timing are not whole-connection guarantees', async ({ page }) => {
  await page.goto('.');
  await expect(page.getByRole('columnheader', { name: 'Shared secret', exact: true })).toBeVisible();
  await expect(page.locator('body')).toContainText('does not authenticate the peer');
  await expect(page.locator('body')).toContainText('do not measure end-to-end TLS latency');
  await expect(page.locator('body')).toContainText('MTU, RTT, loss');
  await expect(page.locator('body')).not.toContainText('The connection survives');
  await expect(page.locator('body')).not.toContainText('dominant real-world post-quantum cost');
});
