// Browser workflow tests against the live stack. Screenshots are written to docs/screenshots/.
import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import nodemailer from 'nodemailer';

const shots = 'docs/screenshots';
const uniq = () => Math.random().toString(36).slice(2, 7);
const PASSWORD = 'ui test password 123';

async function register(page: Page, username: string, displayName: string) {
  await page.goto('/#/register');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Display name (optional)').fill(displayName);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Confirm password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByRole('heading', { name: 'Save your recovery key' })).toBeVisible({ timeout: 60_000 });
  const key = (await page.locator('.recovery-key').innerText()).trim();
  expect(key).toMatch(/^([A-Z0-9]{4}-){12}[A-Z0-9]{4}$/);
  await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled();
  await page.getByLabel('I have stored my recovery key somewhere safe').check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('listbox')).toBeVisible();
  return key;
}

/** Records any request that would leak to a remote host (tracking pixels etc.). */
function watchExternal(ctx: BrowserContext): string[] {
  const hits: string[] = [];
  ctx.on('request', (r) => {
    const u = new URL(r.url());
    if (!['localhost', '127.0.0.1'].includes(u.hostname) && !u.protocol.startsWith('data') && !u.protocol.startsWith('blob') && u.protocol !== 'about:') hits.push(r.url());
  });
  return hits;
}

test('two users: register, E2EE compose/read, security labels, remote-content blocking, search, settings, RTL, mobile', async ({ browser }) => {
  const a = `alice${uniq()}`;
  const b = `bob${uniq()}`;
  const ctxA = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark' });
  const ctxB = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark' });
  const externalA = watchExternal(ctxA);
  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();
  const errors: string[] = [];
  for (const p of [pageA, pageB]) {
    p.on('pageerror', (e) => errors.push(e.message));
    p.on('console', (m) => m.type() === 'error' && !/Failed to load resource/.test(m.text()) && errors.push(m.text()));
  }

  await pageA.goto('/');
  await pageA.screenshot({ path: `${shots}/01-login-desktop.png` });
  await register(pageA, a, 'Alice');
  await pageA.screenshot({ path: `${shots}/02-empty-inbox.png` });
  await register(pageB, b, 'Bob');

  // --- Alice writes to Bob (E2EE) ---
  await pageA.getByRole('button', { name: 'Compose' }).first().click();
  await pageA.locator('#c-to').fill(`${b}@voidmail.test`);
  await pageA.locator('#c-subj').fill('Quarterly plan — خطة الربع');
  await pageA.getByLabel('Write your message…').fill('Hi Bob,\nThe plan is attached.\nمع التحية');
  await expect(pageA.locator('.compose .badge.e2ee')).toHaveText(/End-to-end encrypted/);
  await expect(pageA.locator('.compose .chip')).toContainText('New key (first use)');
  await pageA.locator('.compose input[type=file]').setInputFiles({ name: 'plan.txt', mimeType: 'text/plain', buffer: Buffer.from('secret plan') });
  await expect(pageA.locator('.compose .attachment')).toContainText('plan.txt');
  await expect(pageA.getByText('Draft saved (encrypted)')).toBeVisible({ timeout: 15_000 });
  await pageA.screenshot({ path: `${shots}/03-compose-e2ee.png` });
  await pageA.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(pageA.getByText('Message sent.')).toBeVisible();

  // --- Bob reads it ---
  await pageB.reload();
  await pageB.getByLabel('Password').fill(PASSWORD); // unlock screen after reload: keys live only in memory
  await pageB.getByRole('button', { name: 'Unlock' }).click();
  const row = pageB.getByRole('option').filter({ hasText: 'Quarterly plan' });
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  await expect(pageB.getByRole('heading', { name: 'Quarterly plan — خطة الربع' })).toBeVisible();
  await expect(pageB.locator('.security-strip')).toContainText('End-to-end encrypted');
  await expect(pageB.locator('.security-strip')).toContainText('Signed by the sender’s key');
  await expect(pageB.locator('.body-text')).toContainText('مع التحية');
  const [download] = await Promise.all([pageB.waitForEvent('download'), pageB.getByRole('button', { name: /plan\.txt/ }).click()]);
  expect(download.suggestedFilename()).toBe('plan.txt');
  await pageB.screenshot({ path: `${shots}/04-read-e2ee.png` });

  // --- External HTML mail with a tracking pixel ---
  await nodemailer.createTransport({ host: '127.0.0.1', port: 2525, tls: { rejectUnauthorized: false }, name: 'remote.example.org' }).sendMail({
    from: '"Newsletter" <news@shop.example>',
    to: `${a}@voidmail.test`,
    subject: 'Your weekly deals',
    text: 'Deals inside',
    html: `<h2 style="color:#333">Weekly deals</h2><p>Visit <a href="https://evil.example/login">https://mybank.example</a></p>
           <img src="https://tracker.example/pixel.gif?u=${a}" width="1" height="1"><img src="https://cdn.example/banner.png">
           <script>document.body.innerHTML='pwned'</script><p onclick="alert(1)">click</p>`,
  });
  const ext = pageA.getByRole('option').filter({ hasText: 'Your weekly deals' });
  await expect(async () => {
    await pageA.getByRole('button', { name: 'Inbox' }).click(); // clicking the current folder refreshes it
    await expect(ext).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 30_000 });
  await ext.click();
  await expect(pageA.locator('.security-strip')).toContainText('External · encrypted after arrival');
  await expect(pageA.getByText(/2 remote resources blocked/)).toBeVisible();
  await expect(pageA.getByText('Some links show text that does not match')).toBeVisible();
  const frame = pageA.frameLocator('iframe.mail-frame');
  await expect(frame.locator('h2')).toHaveText('Weekly deals');
  await expect(frame.locator('body')).not.toContainText('pwned');
  expect(await pageA.locator('iframe.mail-frame').getAttribute('sandbox')).not.toContain('allow-scripts');
  await pageA.waitForTimeout(1000);
  expect(externalA).toEqual([]); // no request left the browser to tracker.example / cdn.example
  await pageA.screenshot({ path: `${shots}/05-external-blocked.png` });

  // --- Local search ---
  await pageA.getByRole('searchbox', { name: 'Search' }).fill('deals');
  await expect(pageA.getByRole('option').filter({ hasText: 'Your weekly deals' })).toBeVisible();
  await expect(pageA.getByText('Search runs entirely in your browser')).toBeVisible();
  await pageA.getByRole('button', { name: 'Clear' }).click();

  // --- Sent folder shows E2EE copy ---
  await pageA.getByRole('button', { name: 'Sent' }).click();
  await expect(pageA.getByRole('option').filter({ hasText: 'Quarterly plan' })).toBeVisible();

  // --- Settings: fingerprints, contacts, sessions ---
  await pageA.getByRole('button', { name: 'Settings' }).click();
  await expect(pageA.getByText('Your key fingerprint')).toBeVisible();
  await expect(pageA.getByText(`${b}@voidmail.test`)).toBeVisible();
  await pageA.getByRole('button', { name: 'Mark verified' }).click();
  await expect(pageA.locator('.card').filter({ hasText: 'Contact keys' }).getByText('Verified', { exact: true })).toBeVisible();
  await pageA.screenshot({ path: `${shots}/06-settings.png`, fullPage: false });

  // --- Arabic / RTL ---
  await pageA.getByLabel('Language').selectOption('ar');
  await expect(pageA.locator('html')).toHaveAttribute('dir', 'rtl');
  await pageA.getByRole('button', { name: 'الوارد' }).click();
  await pageA.getByRole('option').first().click();
  await expect(pageA.locator('.security-strip')).toContainText('خارجية');
  await pageA.screenshot({ path: `${shots}/07-rtl-arabic.png` });

  // --- Light theme ---
  await pageA.getByRole('button', { name: 'الإعدادات' }).click();
  await pageA.getByLabel('السمة').selectOption('light');
  await pageA.getByLabel('اللغة').selectOption('en');
  await pageA.getByRole('button', { name: 'Inbox' }).click();
  await pageA.getByRole('option').filter({ hasText: 'Your weekly deals' }).click();
  await expect(pageA.locator('.security-strip')).toBeVisible();
  await pageA.screenshot({ path: `${shots}/08-light-theme.png` });

  // --- Mobile layout ---
  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, colorScheme: 'dark' });
  const pm = await mobile.newPage();
  await pm.goto('/#/login');
  await pm.screenshot({ path: `${shots}/09-mobile-login.png` });
  await pm.getByLabel('Username').fill(b);
  await pm.getByLabel('Password').fill(PASSWORD);
  await pm.getByRole('button', { name: 'Sign in' }).click();
  await expect(pm.getByRole('option').first()).toBeVisible({ timeout: 60_000 });
  await pm.screenshot({ path: `${shots}/10-mobile-inbox.png` });
  await pm.getByRole('option').first().click();
  await expect(pm.locator('.security-strip')).toBeVisible();
  await pm.screenshot({ path: `${shots}/11-mobile-read.png` });
  const overflow = await pm.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await pm.getByRole('button', { name: 'Back' }).click();
  await pm.getByRole('button', { name: 'Menu' }).click();
  await expect(pm.locator('nav.sidebar.open')).toBeInViewport({ ratio: 0.95 });
  await pm.waitForTimeout(350); // slide-in transition
  await pm.screenshot({ path: `${shots}/12-mobile-menu.png` });

  expect(errors).toEqual([]);
});

test('key-change warning blocks sending until accepted', async ({ browser, request }) => {
  const a = `kc${uniq()}`;
  const b = `kd${uniq()}`;
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();
  await register(pageA, a, 'A');
  await register(pageB, b, 'B');
  const send = async (subject: string) => {
    await pageA.getByRole('button', { name: 'Compose' }).first().click();
    await pageA.locator('#c-to').fill(`${b}@voidmail.test`);
    await pageA.locator('#c-subj').fill(subject);
    await pageA.getByLabel('Write your message…').fill('x');
    await pageA.waitForTimeout(700);
    await pageA.getByRole('button', { name: 'Send', exact: true }).click();
  };
  await send('first');
  await expect(pageA.getByText('Message sent.')).toBeVisible();
  // Bob rotates his key.
  await pageB.getByRole('button', { name: 'Settings' }).click();
  await pageB.getByRole('button', { name: 'Rotate encryption key' }).click();
  await expect(pageB.getByText('Retired')).toBeVisible({ timeout: 30_000 });
  await pageA.waitForTimeout(61_000); // client-side lookup cache TTL
  await send('second');
  await expect(pageA.getByRole('dialog', { name: 'A recipient’s encryption key changed' })).toBeVisible();
  await pageA.screenshot({ path: `${shots}/13-key-change-warning.png` });
  await pageA.getByRole('button', { name: 'Accept new key' }).click();
  await pageA.getByRole('button', { name: 'Send', exact: true }).click();
  await expect(pageA.getByText('Message sent.')).toBeVisible();
  void request;
});
