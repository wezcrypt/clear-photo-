import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { ZodError } from 'zod';
import type { Config } from './config.js';
import type { Db } from './db.js';
import type { BlobStore } from './blobstore.js';
import { hmac, ipPrefix, randomToken, safeEqual, sha256 } from './security.js';
import { authRoutes } from './routes/auth.js';
import { mailboxRoutes } from './routes/mailbox.js';
import { settingsRoutes } from './routes/settings.js';

export interface Ctx {
  cfg: Config;
  db: Db;
  blobs: BlobStore;
}

export interface SessionUser {
  id: string;
  username: string;
  sessionHash: Buffer;
  csrf: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    user: SessionUser | null;
  }
}

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    public detail?: unknown,
  ) {
    super(code);
  }
}

export const SESSION_IDLE_MS = 7 * 24 * 3600 * 1000;
export const SESSION_ABSOLUTE_MS = 30 * 24 * 3600 * 1000;

export function cookieName(cfg: Config): string {
  return cfg.secure ? '__Host-vm_session' : 'vm_session';
}

export function csrfFor(cfg: Config, sessionHash: Buffer): string {
  return hmac(cfg.keys.app, 'csrf:' + sessionHash.toString('hex')).toString('base64url');
}

export function requireUser(req: FastifyRequest): SessionUser {
  if (!req.user) throw new HttpError(401, 'unauthenticated');
  return req.user;
}

export async function createSession(ctx: Ctx, reply: FastifyReply, userId: string, userAgent: string | undefined): Promise<Buffer> {
  const token = randomToken(32);
  const hash = sha256(token);
  await ctx.db.query(
    `INSERT INTO sessions(id_hash, user_id, expires_at, user_agent) VALUES ($1,$2, now() + $3::interval, $4)`,
    [hash, userId, `${SESSION_ABSOLUTE_MS / 1000} seconds`, summarizeUserAgent(userAgent)],
  );
  reply.setCookie(cookieName(ctx.cfg), token, {
    httpOnly: true,
    secure: ctx.cfg.secure,
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_ABSOLUTE_MS / 1000,
  });
  return hash;
}

export function clearSessionCookie(ctx: Ctx, reply: FastifyReply): void {
  reply.clearCookie(cookieName(ctx.cfg), { path: '/', secure: ctx.cfg.secure, httpOnly: true, sameSite: 'strict' });
}

/** Keep only a coarse browser/OS description for the device list. */
export function summarizeUserAgent(ua: string | undefined): string {
  if (!ua) return 'Unknown device';
  const browser = /Firefox\//.test(ua) ? 'Firefox' : /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return `${browser} on ${os}`;
}

export async function logSecurityEvent(ctx: Ctx, userId: string | null, type: string, ip?: string): Promise<void> {
  await ctx.db.query('INSERT INTO security_events(user_id, type, ip_prefix) VALUES ($1,$2,$3)', [userId, type, ipPrefix(ip)]);
}

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  // Inline styles are needed for sanitized email HTML rendered in a srcdoc iframe (which inherits this policy).
  "style-src 'self' 'unsafe-inline'",
  // https: is only reachable from email content after the user explicitly allows remote images for a message.
  "img-src 'self' data: blob: https:",
  "font-src 'self'",
  "connect-src 'self'",
  "frame-src 'self' blob:",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

// Unauthenticated endpoints that change state. They are still protected by the Origin check.
const PUBLIC_MUTATIONS = new Set([
  '/api/auth/prelogin',
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/login/totp',
  '/api/auth/logout',
  '/api/recovery/start',
  '/api/recovery/complete',
  '/api/recovery/email-request',
  '/api/recovery/email-complete',
]);

export async function buildApp(ctx: Ctx, opts: { serveStatic?: boolean; log?: boolean } = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    trustProxy: ctx.cfg.TRUST_PROXY === 'true',
    bodyLimit: 8 * 1024 * 1024,
  });

  app.decorateRequest('user', null);

  await app.register(cookie);
  await app.register(rateLimit, { global: false });

  app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer', bodyLimit: ctx.cfg.MAX_MESSAGE_BYTES + 1024 * 1024 }, (_req, body, done) => done(null, body));

  // Minimal, content-free access log: method, route pattern, status, duration. No IPs, no query strings.
  if (opts.log) {
    app.addHook('onResponse', async (req, reply) => {
      const route = req.routeOptions.url ?? 'unmatched';
      console.log(`[http] ${req.method} ${route} ${reply.statusCode} ${Math.round(reply.elapsedTime)}ms`);
    });
  }

  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('Content-Security-Policy', CSP);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Cross-Origin-Opener-Policy', 'same-origin');
    reply.header('Cross-Origin-Resource-Policy', 'same-origin');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()');
    if (ctx.cfg.secure) reply.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
    if (req.url.startsWith('/api/')) reply.header('Cache-Control', 'no-store');
    return payload;
  });

  // Session loading + CSRF/Origin enforcement.
  app.addHook('preHandler', async (req) => {
    if (!req.url.startsWith('/api/')) return;
    const token = req.cookies[cookieName(ctx.cfg)];
    if (token && token.length < 100) {
      const hash = sha256(token);
      const { rows } = await ctx.db.query(
        `SELECT s.user_id, s.last_seen_at, u.username, u.status
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.id_hash = $1 AND s.expires_at > now() AND s.last_seen_at > now() - $2::interval`,
        [hash, `${SESSION_IDLE_MS / 1000} seconds`],
      );
      if (rows.length && rows[0].status === 'active') {
        req.user = { id: rows[0].user_id, username: rows[0].username, sessionHash: hash, csrf: csrfFor(ctx.cfg, hash) };
        if (Date.now() - new Date(rows[0].last_seen_at).getTime() > 5 * 60 * 1000) {
          await ctx.db.query('UPDATE sessions SET last_seen_at = now() WHERE id_hash = $1', [hash]);
        }
      }
    }
    if (req.method === 'GET' || req.method === 'HEAD') return;
    const origin = req.headers.origin;
    if (origin && origin !== ctx.cfg.PUBLIC_ORIGIN) throw new HttpError(403, 'bad_origin');
    const path = req.url.split('?')[0];
    if (PUBLIC_MUTATIONS.has(path)) {
      // Custom header forces a CORS preflight for cross-site requests, which we never allow.
      if (req.headers['x-requested-with'] !== 'voidmail') throw new HttpError(403, 'csrf');
      return;
    }
    if (!req.user) throw new HttpError(401, 'unauthenticated');
    const sent = req.headers['x-csrf-token'];
    if (typeof sent !== 'string' || !safeEqual(sent, req.user.csrf)) throw new HttpError(403, 'csrf');
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof HttpError) {
      return reply.status(err.status).send({ error: err.code, detail: err.detail });
    }
    if (err instanceof ZodError) {
      return reply.status(400).send({ error: 'invalid_request', detail: err.issues.map((i) => i.path.join('.')) });
    }
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status >= 400 && status < 500) {
      return reply.status(status).send({ error: status === 429 ? 'rate_limited' : 'bad_request' });
    }
    // Log only the error type and message, never request data.
    console.error('[error]', (err as Error).name, (err as Error).message);
    return reply.status(500).send({ error: 'internal_error' });
  });

  app.get('/api/health', async () => {
    await ctx.db.query('SELECT 1');
    return { ok: true };
  });

  await app.register(async (api) => authRoutes(api, ctx));
  await app.register(async (api) => mailboxRoutes(api, ctx));
  await app.register(async (api) => settingsRoutes(api, ctx));

  app.all('/api/*', async () => {
    throw new HttpError(404, 'not_found');
  });

  if (opts.serveStatic) {
    const root = path.resolve(ctx.cfg.WEB_DIST);
    if (existsSync(root)) {
      await app.register(fastifyStatic, { root, index: ['index.html'], maxAge: '1h', immutable: false });
      app.setNotFoundHandler((req, reply) => {
        if (req.method === 'GET' && !req.url.startsWith('/api/')) return reply.sendFile('index.html');
        return reply.status(404).send({ error: 'not_found' });
      });
    } else {
      console.warn(`[web] ${root} not found; SPA will not be served (run npm run build:web)`);
    }
  }

  return app;
}
