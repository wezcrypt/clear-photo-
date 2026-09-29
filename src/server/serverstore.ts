import type { Ctx } from './app.js';
import type { Queryable } from './db.js';
import { encryptAttachment, encryptJson, readPublicKey } from '../shared/crypto.js';
import type { BodyPayload, HeaderPayload, SecurityLabel } from '../shared/mail.js';
import { makeSnippet, sanitizeFilename } from '../shared/mail.js';

export interface PlainIncoming {
  subject: string;
  from: { name: string; address: string };
  to: string[];
  cc: string[];
  date: Date;
  text: string;
  html?: string;
  attachments: { filename: string; contentType: string; content: Buffer; cid?: string }[];
  headers?: Record<string, string>;
}

export class QuotaExceeded extends Error {}

export async function activeKey(db: Queryable, userId: string) {
  const { rows } = await db.query(`SELECT fingerprint, public_key FROM user_keys WHERE user_id=$1 AND status='active'`, [userId]);
  if (!rows.length) throw new Error('user has no active key');
  return { fingerprint: rows[0].fingerprint as string, key: await readPublicKey(rows[0].public_key) };
}

export async function usedBytes(db: Queryable, userId: string): Promise<number> {
  const { rows } = await db.query('SELECT coalesce(sum(size_bytes),0)::bigint AS used FROM messages WHERE user_id=$1', [userId]);
  return Number(rows[0].used);
}

/**
 * Encrypts a plaintext message to the user's active OpenPGP key and stores ONLY ciphertext.
 * Used for external inbound mail and service notices. The plaintext exists in this process's memory only.
 */
export async function storeEncryptedForUser(
  ctx: Ctx,
  db: Queryable,
  userId: string,
  msg: PlainIncoming,
  meta: {
    folder: 'inbox' | 'spam';
    kind: 'external_in' | 'system';
    security: SecurityLabel;
    senderAddress: string | null;
    messageId: string | null;
    inReplyTo: string | null;
    rawHash: Buffer | null;
  },
): Promise<string | null> {
  const { fingerprint, key } = await activeKey(db, userId);
  const blobIds: string[] = [];
  const refs: BodyPayload['attachments'] = [];
  let attBytes = 0;
  for (const a of msg.attachments) {
    const { ciphertext, key: attKey } = await encryptAttachment(a.content);
    const storageKey = await ctx.blobs.put(ciphertext);
    const b = await db.query('INSERT INTO blobs(owner_user_id, size_bytes, storage_key) VALUES ($1,$2,$3) RETURNING id', [
      userId,
      ciphertext.length,
      storageKey,
    ]);
    blobIds.push(b.rows[0].id);
    attBytes += ciphertext.length;
    refs.push({ id: b.rows[0].id, name: sanitizeFilename(a.filename), type: a.contentType || 'application/octet-stream', size: a.content.length, key: attKey, ...(a.cid ? { cid: a.cid.slice(0, 200) } : {}) });
  }
  const header: HeaderPayload = {
    v: 1,
    subject: msg.subject,
    from: msg.from,
    to: msg.to,
    cc: msg.cc,
    date: msg.date.toISOString(),
    snippet: makeSnippet(msg.text || ''),
    hasAttachments: refs.length > 0,
  };
  const body: BodyPayload = { v: 1, text: msg.text, html: msg.html, attachments: refs, headers: msg.headers };
  const headerEnc = await encryptJson(header, key);
  const bodyEnc = await encryptJson(body, key);
  const size = headerEnc.length + bodyEnc.length + attBytes;

  const quota = await db.query('SELECT quota_bytes FROM users WHERE id=$1', [userId]);
  if ((await usedBytes(db, userId)) + size > Number(quota.rows[0].quota_bytes) && meta.kind !== 'system') {
    for (const id of blobIds) {
      const r = await db.query('DELETE FROM blobs WHERE id=$1 RETURNING storage_key', [id]);
      await ctx.blobs.delete(r.rows[0].storage_key);
    }
    throw new QuotaExceeded();
  }

  const ins = await db.query(
    `INSERT INTO messages(user_id, folder, kind, security, key_fingerprint, header_enc, body_enc, size_bytes, unread,
                          sender_address, message_id, in_reply_to, raw_hash, received_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$10,$11,$12, now())
     ON CONFLICT (user_id, raw_hash) WHERE raw_hash IS NOT NULL DO NOTHING
     RETURNING id`,
    [userId, meta.folder, meta.kind, meta.security, fingerprint, Buffer.from(headerEnc), Buffer.from(bodyEnc), size,
      meta.senderAddress, meta.messageId, meta.inReplyTo, meta.rawHash],
  );
  if (!ins.rowCount) {
    // Duplicate delivery (e.g. LMTP retry after a lost response): discard the new attachment blobs.
    for (const id of blobIds) {
      const r = await db.query('DELETE FROM blobs WHERE id=$1 RETURNING storage_key', [id]);
      await ctx.blobs.delete(r.rows[0].storage_key);
    }
    return null;
  }
  const messageId = ins.rows[0].id as string;
  for (const id of blobIds) await db.query('INSERT INTO message_blobs(message_id, blob_id) VALUES ($1,$2)', [messageId, id]);
  return messageId;
}

export async function notifyUser(ctx: Ctx, db: Queryable, userId: string, subject: string, text: string): Promise<void> {
  await storeEncryptedForUser(
    ctx,
    db,
    userId,
    {
      subject,
      from: { name: 'VoidMail', address: `no-reply@${ctx.cfg.MAIL_DOMAIN}` },
      to: [],
      cc: [],
      date: new Date(),
      text,
      attachments: [],
    },
    { folder: 'inbox', kind: 'system', security: 'system', senderAddress: `no-reply@${ctx.cfg.MAIL_DOMAIN}`, messageId: null, inReplyTo: null, rawHash: null },
  );
}
