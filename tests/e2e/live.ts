// Helpers for tests that run against the live Docker Compose stack (npm run test:e2e).
import { execFileSync } from 'node:child_process';
import { VoidClient, type Transport } from '../../src/shared/client.js';

export const BASE = process.env.E2E_BASE ?? 'http://localhost:8080';
export const MAILPIT = process.env.E2E_MAILPIT ?? 'http://localhost:8025';
export const MAILPIT_TLS = process.env.E2E_MAILPIT_TLS ?? 'http://localhost:8026';
export const SMTP_PORT = Number(process.env.E2E_SMTP_PORT ?? 2525);

export function fetchTransport(): Transport {
  const jar = new Map<string, string>();
  return async (method, path, opts = {}) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}), Origin: BASE };
    if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    let body: BodyInit | undefined;
    if (opts.bytes) body = opts.bytes as BodyInit;
    else if (opts.json !== undefined) {
      body = JSON.stringify(opts.json);
      headers['content-type'] = 'application/json';
    }
    const res = await fetch(BASE + path, { method, headers, body });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(';');
      const i = kv.indexOf('=');
      const k = kv.slice(0, i);
      const v = kv.slice(i + 1);
      if (!v) jar.delete(k);
      else jar.set(k, v);
    }
    if (opts.binary && res.ok) return { status: res.status, data: null, bytes: new Uint8Array(await res.arrayBuffer()) };
    const ct = res.headers.get('content-type') ?? '';
    return { status: res.status, data: ct.includes('json') ? await res.json() : await res.text() };
  };
}

export const uniq = () => Math.random().toString(36).slice(2, 8);

export async function newUser(prefix: string, extra: { recoveryEmail?: string } = {}) {
  const client = new VoidClient(fetchTransport());
  const username = `${prefix}${uniq()}`;
  const password = 'e2e test password 123';
  const { recoveryKey } = await client.register({ username, password, displayName: prefix, ...extra });
  return { client, username, password, recoveryKey, address: `${username}@voidmail.test` };
}

export async function waitFor<T>(fn: () => Promise<T | null | undefined | false>, timeoutMs = 60_000, stepMs = 1000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

export async function mailpitSearch(base: string, query: string): Promise<any[]> {
  const r = await fetch(`${base}/api/v1/search?query=${encodeURIComponent(query)}`);
  return (await r.json()).messages ?? [];
}

export async function mailpitRaw(base: string, id: string): Promise<string> {
  return (await fetch(`${base}/api/v1/message/${id}/raw`)).text();
}

export function compose(args: string[], input?: string): string {
  return execFileSync('docker', ['compose', ...args], { encoding: 'utf8', input, cwd: new URL('../..', import.meta.url).pathname, stdio: ['pipe', 'pipe', 'pipe'] });
}
