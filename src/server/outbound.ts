import nodemailer from 'nodemailer';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Ctx } from './app.js';
import type { Config } from './config.js';
import type { Queryable } from './db.js';
import { openServer, sealServer } from './security.js';

export interface MimeInput {
  from: { name: string; address: string };
  to: string[];
  cc: string[];
  subject: string;
  text: string;
  html?: string;
  attachments: { filename: string; contentType: string; content: Buffer }[];
  messageId: string;
  inReplyTo?: string;
  references?: string[];
  date?: Date;
  headers?: Record<string, string>;
}

let dkimCache: { key: string } | null | undefined;
function dkimKey(cfg: Config): string | null {
  if (dkimCache === undefined) {
    dkimCache = cfg.DKIM_PRIVATE_KEY_FILE ? { key: readFileSync(cfg.DKIM_PRIVATE_KEY_FILE, 'utf8') } : null;
  }
  return dkimCache?.key ?? null;
}

export function newMessageId(cfg: Config): string {
  return `<${randomUUID()}@${cfg.MAIL_DOMAIN}>`;
}

/**
 * Builds RFC 5322 / MIME with nodemailer (stream transport, no network) and DKIM-signs when a key is configured.
 * Bcc is intentionally never passed: BCC recipients exist only in the SMTP envelope.
 */
export async function buildMime(cfg: Config, m: MimeInput): Promise<Buffer> {
  const key = dkimKey(cfg);
  const transport = nodemailer.createTransport({
    streamTransport: true,
    buffer: true,
    newline: 'windows',
    ...(key ? { dkim: { domainName: cfg.MAIL_DOMAIN, keySelector: cfg.DKIM_SELECTOR, privateKey: key } } : {}),
  });
  const info = await transport.sendMail({
    from: { name: m.from.name, address: m.from.address },
    to: m.to,
    cc: m.cc.length ? m.cc : undefined,
    subject: m.subject,
    text: m.text,
    html: m.html,
    attachments: m.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, content: a.content })),
    messageId: m.messageId,
    inReplyTo: m.inReplyTo,
    references: m.references,
    date: m.date ?? new Date(),
    headers: m.headers,
    // Deny nodemailer any filesystem/URL access for attachment content.
    disableFileAccess: true,
    disableUrlAccess: true,
  } as Parameters<ReturnType<typeof nodemailer.createTransport>["sendMail"]>[0]);
  return info.message as Buffer;
}

export function envelopeFrom(cfg: Config, queueId: string, requireTls: boolean): string {
  return `bounces+${queueId.replace(/-/g, '')}${requireTls ? '.tls' : ''}@${cfg.MAIL_DOMAIN}`;
}

/** Parses the VERP bounce address back to a queue id. */
export function parseBounceAddress(cfg: Config, address: string): string | null {
  const m = new RegExp(`^bounces\\+([0-9a-f]{32})(?:\\.tls)?@${cfg.MAIL_DOMAIN.replace(/\./g, '\\.')}$`, 'i').exec(address);
  if (!m) return null;
  const h = m[1].toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export async function enqueueOutbound(
  cfg: Config,
  db: Queryable,
  o: { userId: string | null; messageId: string | null; kind: 'user' | 'system'; requireTls: boolean; rfcMessageId: string; recipients: string[]; mime: Buffer },
): Promise<string> {
  const id = randomUUID();
  const payload = await sealServer(cfg.keys.queue, o.mime, 'queue:' + id);
  await db.query(
    `INSERT INTO outbound_queue(id, user_id, message_id, kind, require_tls, envelope_from, rfc_message_id, payload_enc)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, o.userId, o.messageId, o.kind, o.requireTls, envelopeFrom(cfg, id, o.requireTls), o.rfcMessageId, payload],
  );
  for (const r of o.recipients) {
    await db.query('INSERT INTO outbound_recipients(queue_id, address) VALUES ($1,$2) ON CONFLICT DO NOTHING', [id, r]);
  }
  return id;
}

export async function openQueuePayload(cfg: Config, id: string, payload: Buffer): Promise<Buffer> {
  return openServer(cfg.keys.queue, payload, 'queue:' + id);
}

/** Service mail (password-reset links). Plain text, no user content, standard (non-E2EE) delivery. */
export async function enqueueSystemEmail(ctx: Ctx, m: { to: string; subject: string; text: string }): Promise<string> {
  const rfcMessageId = newMessageId(ctx.cfg);
  const mime = await buildMime(ctx.cfg, {
    from: { name: 'VoidMail', address: `no-reply@${ctx.cfg.MAIL_DOMAIN}` },
    to: [m.to],
    cc: [],
    subject: m.subject,
    text: m.text,
    attachments: [],
    messageId: rfcMessageId,
    headers: { 'Auto-Submitted': 'auto-generated' },
  });
  return enqueueOutbound(ctx.cfg, ctx.db, {
    userId: null,
    messageId: null,
    kind: 'system',
    requireTls: false,
    rfcMessageId,
    recipients: [m.to],
    mime,
  });
}
