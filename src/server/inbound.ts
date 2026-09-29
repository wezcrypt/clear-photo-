import { simpleParser, type AddressObject, type ParsedMail } from 'mailparser';
import type { Ctx } from './app.js';
import { tx } from './db.js';
import { sha256 } from './security.js';
import { parseBounceAddress } from './outbound.js';
import { QuotaExceeded, notifyUser, storeEncryptedForUser } from './serverstore.js';
import { normalizeAddress } from '../shared/mail.js';

export type RecipientKind = { type: 'user'; userId: string } | { type: 'bounce'; queueId: string };

export class InboundError extends Error {
  constructor(
    message: string,
    public responseCode: number,
  ) {
    super(message);
  }
}

/** Resolves an envelope recipient. Used both by Postfix's recipient lookup (tcp_table) and at LMTP time. */
export async function resolveRecipient(ctx: Ctx, rawAddress: string): Promise<RecipientKind | null> {
  const address = normalizeAddress(rawAddress);
  if (!address) return null;
  const [local, domain] = address.split('@');
  if (domain !== ctx.cfg.MAIL_DOMAIN) return null;
  if (local.startsWith('bounces+')) {
    const queueId = parseBounceAddress(ctx.cfg, address);
    if (!queueId) return null;
    const { rowCount } = await ctx.db.query('SELECT 1 FROM outbound_queue WHERE id=$1', [queueId]);
    return rowCount ? { type: 'bounce', queueId } : null;
  }
  const target = ['postmaster', 'abuse'].includes(local) ? (ctx.cfg.POSTMASTER_USER ?? '') : local;
  if (!target) return null;
  const { rows } = await ctx.db.query(
    `SELECT u.id FROM users u WHERE u.username=$1 AND u.status='active'
        AND EXISTS (SELECT 1 FROM user_keys k WHERE k.user_id=u.id AND k.status='active')`,
    [target],
  );
  return rows.length ? { type: 'user', userId: rows[0].id } : null;
}

function addresses(obj: AddressObject | AddressObject[] | undefined): string[] {
  if (!obj) return [];
  const list = Array.isArray(obj) ? obj : [obj];
  return list.flatMap((o) => o.value.flatMap((v) => (v.address ? [v.address] : (v.group ?? []).map((g) => g.address ?? '').filter(Boolean))));
}

const KEPT_HEADERS = ['authentication-results', 'received-spf', 'list-unsubscribe', 'reply-to', 'x-spam-status'];

function isSpam(parsed: ParsedMail): boolean {
  // VoidMail does not run its own content filter. It honours a verdict from an upstream filter
  // (e.g. rspamd/SpamAssassin milter in front of Postfix), see OPERATIONS.md.
  const flag = String(parsed.headers.get('x-spam-flag') ?? '').toLowerCase();
  const status = String(parsed.headers.get('x-spam-status') ?? '').toLowerCase();
  return flag === 'yes' || status.startsWith('yes');
}

/** Handles one inbound message for all LMTP recipients. Returns one result per recipient (LMTP semantics). */
export async function processInbound(ctx: Ctx, raw: Buffer, rcpts: string[]): Promise<(string | InboundError)[]> {
  let parsed: ParsedMail;
  try {
    parsed = await simpleParser(raw, { skipImageLinks: true, skipTextLinks: true, maxHtmlLengthToParse: 5_000_000 });
  } catch {
    return rcpts.map(() => new InboundError('5.6.0 Malformed message', 554));
  }
  const rawHash = sha256(raw);
  const results: (string | InboundError)[] = [];
  for (const rcpt of rcpts) {
    try {
      const r = await resolveRecipient(ctx, rcpt);
      if (!r) {
        results.push(new InboundError('5.1.1 No such user', 550));
        continue;
      }
      if (r.type === 'bounce') {
        await handleBounce(ctx, r.queueId, raw, parsed);
        results.push('2.0.0 Bounce processed');
        continue;
      }
      const from = parsed.from?.value[0];
      const headers: Record<string, string> = {};
      for (const h of KEPT_HEADERS) {
        const v = parsed.headers.get(h);
        if (v) headers[h] = (typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 2000);
      }
      const id = await tx(ctx.db, (c) =>
        storeEncryptedForUser(
          ctx,
          c,
          r.userId,
          {
            subject: parsed.subject ?? '',
            from: { name: from?.name ?? '', address: from?.address ?? '' },
            to: addresses(parsed.to),
            cc: addresses(parsed.cc),
            date: parsed.date ?? new Date(),
            text: parsed.text ?? '',
            html: typeof parsed.html === 'string' ? parsed.html : undefined,
            attachments: parsed.attachments.map((a) => ({
              filename: a.filename ?? 'attachment',
              contentType: a.contentType,
              content: a.content,
              cid: a.contentId ? a.contentId.replace(/^<|>$/g, '') : undefined,
            })),
            headers,
          },
          {
            folder: isSpam(parsed) ? 'spam' : 'inbox',
            kind: 'external_in',
            security: 'external_encrypted_on_arrival',
            senderAddress: from?.address ? (normalizeAddress(from.address) ?? null) : null,
            messageId: parsed.messageId ? parsed.messageId.slice(0, 998) : null,
            inReplyTo: parsed.inReplyTo ? String(parsed.inReplyTo).slice(0, 998) : null,
            rawHash,
          },
        ),
      );
      results.push(id ? '2.0.0 Delivered' : '2.0.0 Duplicate ignored');
    } catch (e) {
      if (e instanceof QuotaExceeded) results.push(new InboundError('5.2.2 Mailbox full', 552));
      else {
        console.error('[inbound] delivery error:', (e as Error).message);
        results.push(new InboundError('4.3.0 Temporary failure', 451));
      }
    }
  }
  return results;
}

interface DsnRecipient {
  address: string;
  action: string;
  status: string;
  diagnostic: string;
}

export function parseDeliveryStatus(text: string): DsnRecipient[] {
  const blocks = text.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ').split(/\n\s*\n/);
  const out: DsnRecipient[] = [];
  for (const block of blocks) {
    const fields: Record<string, string> = {};
    for (const line of block.split('\n')) {
      const m = /^([A-Za-z-]+):\s*(.*)$/.exec(line);
      if (m) fields[m[1].toLowerCase()] = m[2].trim();
    }
    const rcpt = fields['final-recipient'] ?? fields['original-recipient'];
    if (!rcpt || !fields['action']) continue;
    const address = normalizeAddress(rcpt.replace(/^rfc822;\s*/i, ''));
    if (!address) continue;
    out.push({
      address,
      action: fields['action'].toLowerCase(),
      status: fields['status'] ?? '',
      diagnostic: (fields['diagnostic-code'] ?? '').replace(/^smtp;\s*/i, '').slice(0, 300),
    });
  }
  return out;
}

/** Extracts the message/delivery-status body part (RFC 3464) from a raw DSN. */
export function extractDeliveryStatus(raw: string): string | null {
  const m = /content-type:[ \t]*message\/(?:global-)?delivery-status[^\n]*\n(?:[ \t][^\n]*\n|[^\r\n][^\n]*\n)*?\r?\n([\s\S]*?)(?:\r?\n--[^\r\n]*|$)/i.exec(raw);
  return m ? m[1] : null;
}

async function handleBounce(ctx: Ctx, queueId: string, raw: Buffer, parsed: ParsedMail): Promise<void> {
  const part = extractDeliveryStatus(raw.toString('utf8'));
  const recipients = parseDeliveryStatus(part ?? parsed.text ?? '');
  const q = await ctx.db.query('SELECT user_id, message_id FROM outbound_queue WHERE id=$1', [queueId]);
  if (!q.rowCount) return;
  const failed: DsnRecipient[] = [];
  for (const r of recipients) {
    const status = r.action === 'failed' ? 'bounced' : r.action === 'delayed' ? 'deferred' : r.action === 'delivered' || r.action === 'relayed' || r.action === 'expanded' ? 'delivered' : null;
    if (!status) continue;
    const upd = await ctx.db.query(
      `UPDATE outbound_recipients SET status=$3, diagnostic=$4, updated_at=now()
        WHERE queue_id=$1 AND address=$2 AND status NOT IN ('bounced') RETURNING 1`,
      [queueId, r.address, status, `${r.status} ${r.diagnostic}`.trim().slice(0, 300)],
    );
    if (upd.rowCount && status === 'bounced') failed.push(r);
  }
  // Tell the sender, once, in their own mailbox. A bounce never generates outbound mail (loop prevention).
  if (failed.length && q.rows[0].user_id) {
    await notifyUser(
      ctx,
      ctx.db,
      q.rows[0].user_id,
      'Delivery failed',
      `Your message could not be delivered to:\n\n${failed.map((f) => `• ${f.address} — ${f.status} ${f.diagnostic}`.trim()).join('\n')}\n\n` +
        `Open the message in Sent to see its delivery status.`,
    );
  }
}
