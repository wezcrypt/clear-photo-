import nodemailer from 'nodemailer';
import type { Ctx } from './app.js';
import { openQueuePayload } from './outbound.js';
import { notifyUser } from './serverstore.js';

export const MAX_ATTEMPTS = 8;
/** Backoff for handing mail to the local Postfix relay (Postfix itself retries remote delivery for days). */
export function backoffSeconds(attempt: number): number {
  return [30, 120, 300, 900, 1800, 3600, 7200, 14400][Math.min(attempt - 1, 7)];
}

export interface RelayTransport {
  send(envelope: { from: string; to: string[] }, raw: Buffer): Promise<{ accepted: string[]; rejected: string[] }>;
}

export function smtpRelay(ctx: Ctx): RelayTransport {
  const transport = nodemailer.createTransport({
    host: ctx.cfg.SMTP_RELAY_HOST,
    port: ctx.cfg.SMTP_RELAY_PORT,
    secure: false,
    // Private network hop to our own Postfix submission listener, restricted by mynetworks.
    ignoreTLS: true,
    name: 'voidmail-worker',
    connectionTimeout: 15000,
    greetingTimeout: 15000,
    socketTimeout: 60000,
    logger: false,
  });
  return {
    async send(envelope, raw) {
      const info = await transport.sendMail({
        envelope,
        raw,
        // Ask for delivery status notifications; RET=HDRS so bounces carry headers, not message content.
        dsn: { ret: 'HDRS', notify: ['SUCCESS', 'FAILURE', 'DELAY'] },
      } as Parameters<ReturnType<typeof nodemailer.createTransport>["sendMail"]>[0]);
      const norm = (l: unknown[]) => l.map((a) => (typeof a === 'string' ? a : (a as { address: string }).address).toLowerCase());
      return { accepted: norm(info.accepted as unknown[]), rejected: norm(info.rejected as unknown[]) };
    },
  };
}

interface QueueRow {
  id: string;
  user_id: string | null;
  kind: string;
  envelope_from: string;
  payload_enc: Buffer | null;
  attempts: number;
}

/**
 * Claims due queue rows with a lease (FOR UPDATE SKIP LOCKED) so concurrent workers never send the same row.
 * A row whose lease expired (worker crashed mid-send) is retried: delivery is at-least-once towards Postfix,
 * and Postfix + remote servers de-duplicate nothing, so a crash in that narrow window can duplicate. Documented.
 */
export async function claim(ctx: Ctx, limit = 10): Promise<QueueRow[]> {
  const { rows } = await ctx.db.query(
    `UPDATE outbound_queue q SET status='sending', lease_until = now() + interval '5 minutes', attempts = attempts + 1, updated_at = now()
      WHERE q.id IN (
        SELECT id FROM outbound_queue
         WHERE (status='queued' AND next_attempt_at <= now()) OR (status='sending' AND lease_until < now())
         ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
      RETURNING q.id, q.user_id, q.kind, q.envelope_from, q.payload_enc, q.attempts`,
    [limit],
  );
  return rows;
}

export async function deliverRow(ctx: Ctx, relay: RelayTransport, row: QueueRow): Promise<'relayed' | 'retry' | 'failed'> {
  const { db } = ctx;
  if (!row.payload_enc) {
    await db.query(`UPDATE outbound_queue SET status='failed', last_error='missing payload', updated_at=now() WHERE id=$1`, [row.id]);
    return 'failed';
  }
  const rcpts = (await db.query(`SELECT address FROM outbound_recipients WHERE queue_id=$1 AND status='queued'`, [row.id])).rows.map((r) => r.address as string);
  if (!rcpts.length) {
    await db.query(`UPDATE outbound_queue SET status='relayed', payload_enc=NULL, lease_until=NULL, updated_at=now() WHERE id=$1`, [row.id]);
    return 'relayed';
  }
  let raw: Buffer | null = null;
  try {
    raw = await openQueuePayload(ctx.cfg, row.id, row.payload_enc);
    const res = await relay.send({ from: row.envelope_from, to: rcpts }, raw);
    await db.query(
      `UPDATE outbound_recipients SET status='relayed', updated_at=now() WHERE queue_id=$1 AND address = ANY($2::text[]) AND status='queued'`,
      [row.id, res.accepted],
    );
    if (res.rejected.length) {
      await db.query(
        `UPDATE outbound_recipients SET status='failed', diagnostic='rejected by relay', updated_at=now() WHERE queue_id=$1 AND address = ANY($2::text[])`,
        [row.id, res.rejected],
      );
    }
    // Plaintext payload is deleted as soon as Postfix has accepted responsibility.
    await db.query(
      `UPDATE outbound_queue SET status='relayed', payload_enc=NULL, lease_until=NULL, last_error=NULL, updated_at=now() WHERE id=$1 AND status='sending'`,
      [row.id],
    );
    return 'relayed';
  } catch (e) {
    const err = e as { responseCode?: number; message: string; code?: string };
    const permanent = typeof err.responseCode === 'number' && err.responseCode >= 500;
    const diag = `${err.responseCode ?? err.code ?? 'error'}: ${String(err.message).slice(0, 200)}`;
    if (permanent || row.attempts >= MAX_ATTEMPTS) {
      await db.query(
        `UPDATE outbound_queue SET status='failed', payload_enc=NULL, lease_until=NULL, last_error=$2, updated_at=now() WHERE id=$1`,
        [row.id, diag],
      );
      await db.query(`UPDATE outbound_recipients SET status='failed', diagnostic=$2, updated_at=now() WHERE queue_id=$1 AND status='queued'`, [row.id, diag]);
      if (row.user_id && row.kind === 'user') {
        await notifyUser(ctx, db, row.user_id, 'Delivery failed', `VoidMail could not hand your message to the mail server.\n\n${diag}\n\nRecipients:\n${rcpts.map((r) => '• ' + r).join('\n')}`);
      }
      return 'failed';
    }
    await db.query(
      `UPDATE outbound_queue SET status='queued', lease_until=NULL, last_error=$2, next_attempt_at = now() + make_interval(secs => $3), updated_at=now() WHERE id=$1`,
      [row.id, diag, backoffSeconds(row.attempts)],
    );
    return 'retry';
  } finally {
    raw?.fill(0);
  }
}

export async function runOnce(ctx: Ctx, relay: RelayTransport): Promise<number> {
  const rows = await claim(ctx);
  for (const r of rows) await deliverRow(ctx, relay, r);
  return rows.length;
}
