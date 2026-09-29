import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../src/server/config.js';
import { createPool, migrate } from '../src/server/db.js';
import { FsBlobStore } from '../src/server/blobstore.js';
import { buildApp, type Ctx } from '../src/server/app.js';
import { VoidClient, type Transport } from '../src/shared/client.js';

export const TEST_DB = process.env.TEST_DATABASE_URL ?? 'postgres://voidmail:testpw@127.0.0.1:55432/voidmail_test';

export function testEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const hex = () => randomBytes(32).toString('hex');
  return {
    NODE_ENV: 'test',
    DATABASE_URL: TEST_DB,
    MAIL_DOMAIN: 'voidmail.test',
    PUBLIC_ORIGIN: 'http://localhost:8080',
    APP_SECRET: hex(),
    AUTH_PEPPER: hex(),
    QUEUE_KEY: hex(),
    TOTP_KEY: hex(),
    BLOB_DIR: mkdtempSync(path.join(os.tmpdir(), 'vm-blobs-')),
    CLIENT_KDF_M: '19456',
    CLIENT_KDF_T: '2',
    ARGON2_MEMORY_KIB: '4096',
    ARGON2_TIME: '2',
    RATE_LIMIT_MULTIPLIER: '100',
    SENDS_PER_MINUTE: '1000',
    ...extra,
  };
}

export async function makeCtx(extra: Record<string, string> = {}): Promise<Ctx> {
  const cfg = loadConfig(testEnv(extra));
  const db = createPool(cfg.DATABASE_URL, 5);
  await db.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await migrate(db);
  return { cfg, db, blobs: new FsBlobStore(cfg.BLOB_DIR) };
}

/** In-process HTTP transport with a per-client cookie jar (like a browser). */
export function injectTransport(app: FastifyInstance): Transport & { cookies: Map<string, string> } {
  const cookies = new Map<string, string>();
  const t = (async (method, url, opts = {}) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (cookies.size) headers.cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    let payload: string | Buffer | undefined;
    if (opts.bytes) payload = Buffer.from(opts.bytes);
    else if (opts.json !== undefined) {
      payload = JSON.stringify(opts.json);
      headers['content-type'] = 'application/json';
    }
    const res = await app.inject({ method: method as 'GET', url, headers, payload });
    const sc = res.headers['set-cookie'];
    for (const c of (Array.isArray(sc) ? sc : sc ? [sc] : []) as string[]) {
      const [kv, ...attrs] = c.split(';');
      const [k, v] = kv.split('=');
      if (attrs.some((a) => /max-age=0|expires=thu, 01 jan 1970/i.test(a.trim())) || v === '') cookies.delete(k);
      else cookies.set(k, v);
    }
    const ct = String(res.headers['content-type'] ?? '');
    return {
      status: res.statusCode,
      data: ct.includes('application/json') ? res.json() : res.body,
      bytes: opts.binary ? new Uint8Array(res.rawPayload) : undefined,
    };
  }) as Transport & { cookies: Map<string, string> };
  t.cookies = cookies;
  return t;
}

export async function newClient(app: FastifyInstance) {
  const transport = injectTransport(app);
  return { client: new VoidClient(transport), transport };
}

export async function registered(app: FastifyInstance, username: string, password = 'correct horse battery staple', extra: { recoveryEmail?: string } = {}) {
  const { client, transport } = await newClient(app);
  const { recoveryKey } = await client.register({ username, password, displayName: username[0].toUpperCase() + username.slice(1), ...extra });
  return { client, transport, recoveryKey, password };
}
