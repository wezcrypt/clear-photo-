import { defineConfig } from '@playwright/test';
import { existsSync, readdirSync } from 'node:fs';

/** Prefer an explicitly provided or preinstalled Chromium (e.g. PLAYWRIGHT_BROWSERS_PATH) over downloading one. */
function chromium(): string | undefined {
  if (process.env.PW_CHROMIUM) return process.env.PW_CHROMIUM;
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (!root || !existsSync(root)) return undefined;
  const dir = readdirSync(root).filter((d) => /^chromium-\d+$/.test(d)).sort().pop();
  const exe = dir ? `${root}/${dir}/chrome-linux/chrome` : '';
  return exe && existsSync(exe) ? exe : undefined;
}

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.ui\.ts$/,
  timeout: 240_000,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE ?? 'http://localhost:8080',
    launchOptions: { executablePath: chromium() },
  },
});
