import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { type Ctx, HttpError, requireUser } from '../app.js';
import { type Queryable, tx } from '../db.js';
import { b64ToBuf } from '../security.js';
import { normalizeAddress, sanitizeFilename } from '../../shared/mail.js';
import { decryptAttachment } from '../../shared/crypto.js';
import { buildMime, enqueueOutbound, newMessageId } from '../outbound.js';
import { usedBytes } from '../serverstore.js';
import { purgeMessages } from '../retention.js';
import { rl } from '../ratelimits.js';

const uuid = z.string().uuid();
const b64 = (max: number) => z.string().max(max).regex(/^[A-Za-z0-9+/]*={0,2}$/);
const fp = z.string().regex(/^[0-9a-f]{40,64}$/);
const encCopy = { headerEnc: b64(200_000), bodyEnc: b64(8_000_000), keyFingerprint: fp };
const USER_FOLDERS = ['inbox', 'archive', 'spam', 'trash'] as const;

function row(m: Record<string, any>, withBody = false) {
  return {
    id: m.id,
    folder: m.folder,
    kind: m.kind,
    security: m.security,
    unread: m.unread,
    starred: m.starred,
    size: Number(m.size_bytes),
    receivedAt: m.received_at,
    keyFingerprint: m.key_fingerprint,
    senderAddress: m.sender_address,
    messageId: m.message_id,
    inReplyTo: m.in_reply_to,
    labels: m.labels ?? [],
    headerEnc: Buffer.from(m.header_enc).toString('base64'),
    ...(withBody ? { bodyEnc: Buffer.from(m.body_enc).toString('base64') } : {}),
  };
}

export async function canAccessBlob(db: Queryable, userId: string, blobId: string): Promise<boolean> {
  const { rows } = await db.query(
    `SELECT 1 FROM blobs b WHERE b.id = $1 AND (b.owner_user_id = $2 OR EXISTS (
        SELECT 1 FROM message_blobs mb JOIN messages m ON m.id = mb.message_id WHERE mb.blob_id = b.id AND m.user_id = $2))`,
    [blobId, userId],
  );
  return rows.length > 0;
}

async function blobsSize(db: Queryable, ids: string[]): Promise<number> {
  if (!ids.length) return 0;
  const { rows } = await db.query('SELECT coalesce(sum(size_bytes),0)::bigint AS s FROM blobs WHERE id = ANY($1::uuid[])', [ids]);
  return Number(rows[0].s);
}

async function linkBlobs(db: Queryable, messageId: string, ids: string[]) {
  for (const id of ids) await db.query('INSERT INTO message_blobs(message_id, blob_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [messageId, id]);
}

export async function mailboxRoutes(app: FastifyInstance, ctx: Ctx): Promise<void> {
  const { cfg, db } = ctx;

  app.get('/api/messages', async (req) => {
    const user = requireUser(req);
    const q = z
      .object({
        folder: z.enum(['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash', 'starred']).optional(),
        label: uuid.optional(),
        before: z.string().max(80).optional(),
        limit: z.coerce.number().int().min(1).max(100).default(50),
      })
      .parse(req.query);
    const params: unknown[] = [user.id];
    let where = 'm.user_id = $1';
    if (q.label) {
      params.push(q.label);
      where += ` AND EXISTS (SELECT 1 FROM message_labels ml WHERE ml.message_id = m.id AND ml.label_id = $${params.length})`;
      where += ` AND m.folder NOT IN ('trash','spam')`;
    } else if (q.folder === 'starred') {
      where += ` AND m.starred AND m.folder NOT IN ('trash','spam')`;
    } else {
      params.push(q.folder ?? 'inbox');
      where += ` AND m.folder = $${params.length}`;
    }
    if (q.before) {
      const [ts, id] = q.before.split('|');
      if (!ts || !id || Number.isNaN(Date.parse(ts)) || !uuid.safeParse(id).success) throw new HttpError(400, 'invalid_cursor');
      params.push(ts, id);
      where += ` AND (m.received_at, m.id) < ($${params.length - 1}::timestamptz, $${params.length}::uuid)`;
    }
    params.push(q.limit + 1);
    const { rows } = await db.query(
      `SELECT m.*, (SELECT array_agg(label_id) FROM message_labels ml WHERE ml.message_id = m.id) AS labels
         FROM messages m WHERE ${where}
        ORDER BY m.received_at DESC, m.id DESC LIMIT $${params.length}`,
      params,
    );
    const more = rows.length > q.limit;
    const page = rows.slice(0, q.limit);
    const last = page[page.length - 1];
    return {
      messages: page.map((m) => row(m)),
      next: more && last ? `${new Date(last.received_at).toISOString()}|${last.id}` : null,
    };
  });

  app.get('/api/messages/counts', async (req) => {
    const user = requireUser(req);
    const { rows } = await db.query(
      `SELECT folder, count(*) FILTER (WHERE unread)::int AS unread, count(*)::int AS total FROM messages WHERE user_id=$1 GROUP BY folder`,
      [user.id],
    );
    return Object.fromEntries(rows.map((r) => [r.folder, { unread: r.unread, total: r.total }]));
  });

  app.get('/api/messages/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { rows } = await db.query(
      `SELECT m.*, (SELECT array_agg(label_id) FROM message_labels ml WHERE ml.message_id = m.id) AS labels
         FROM messages m WHERE m.id = $1 AND m.user_id = $2`,
      [id, user.id],
    );
    if (!rows.length) throw new HttpError(404, 'not_found');
    const blobs = await db.query('SELECT blob_id FROM message_blobs WHERE message_id = $1', [id]);
    return { ...row(rows[0], true), blobIds: blobs.rows.map((b) => b.blob_id) };
  });

  app.get('/api/messages/:id/delivery', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { rows } = await db.query(
      `SELECT q.status AS queue_status, q.require_tls, q.attempts, r.address, r.status, r.diagnostic, r.updated_at
         FROM outbound_queue q JOIN outbound_recipients r ON r.queue_id = q.id
         JOIN messages m ON m.id = q.message_id
        WHERE q.message_id = $1 AND m.user_id = $2`,
      [id, user.id],
    );
    return rows.map((r) => ({
      address: r.address,
      status: r.status,
      queueStatus: r.queue_status,
      requireTls: r.require_tls,
      attempts: r.attempts,
      diagnostic: r.diagnostic,
      updatedAt: r.updated_at,
    }));
  });

  app.patch('/api/messages/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const body = z
      .object({ unread: z.boolean().optional(), starred: z.boolean().optional(), folder: z.enum([...USER_FOLDERS, 'restore']).optional() })
      .parse(req.body);
    await updateMessages(db, user.id, [id], body);
    return { ok: true };
  });

  app.post('/api/messages/bulk', async (req) => {
    const user = requireUser(req);
    const body = z
      .object({
        ids: z.array(uuid).min(1).max(200),
        unread: z.boolean().optional(),
        starred: z.boolean().optional(),
        folder: z.enum([...USER_FOLDERS, 'restore']).optional(),
        delete: z.boolean().optional(),
      })
      .parse(req.body);
    if (body.delete) {
      const n = await purgeMessages(ctx, user.id, body.ids, true);
      return { deleted: n };
    }
    await updateMessages(db, user.id, body.ids, body);
    return { ok: true };
  });

  app.delete('/api/messages/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const n = await purgeMessages(ctx, user.id, [id], true);
    if (!n) throw new HttpError(409, 'move_to_trash_first');
    return { ok: true };
  });

  app.put('/api/messages/:id/labels', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const { labelIds } = z.object({ labelIds: z.array(uuid).max(50) }).parse(req.body);
    await tx(db, async (c) => {
      const m = await c.query('SELECT 1 FROM messages WHERE id=$1 AND user_id=$2', [id, user.id]);
      if (!m.rowCount) throw new HttpError(404, 'not_found');
      const owned = await c.query('SELECT id FROM labels WHERE user_id=$1 AND id = ANY($2::uuid[])', [user.id, labelIds]);
      if (owned.rowCount !== new Set(labelIds).size) throw new HttpError(404, 'label_not_found');
      await c.query('DELETE FROM message_labels WHERE message_id=$1', [id]);
      for (const l of new Set(labelIds)) await c.query('INSERT INTO message_labels(message_id,label_id) VALUES ($1,$2)', [id, l]);
    });
    return { ok: true };
  });

  // ---- labels ----
  app.get('/api/labels', async (req) => {
    const user = requireUser(req);
    const { rows } = await db.query('SELECT id, name, color FROM labels WHERE user_id=$1 ORDER BY name', [user.id]);
    return rows;
  });
  app.post('/api/labels', async (req) => {
    const user = requireUser(req);
    const body = z.object({ name: z.string().trim().min(1).max(40), color: z.enum(['violet', 'blue', 'green', 'amber', 'red', 'gray']).default('violet') }).parse(req.body);
    const count = await db.query('SELECT count(*)::int AS n FROM labels WHERE user_id=$1', [user.id]);
    if (count.rows[0].n >= 100) throw new HttpError(409, 'too_many_labels');
    try {
      const { rows } = await db.query('INSERT INTO labels(user_id,name,color) VALUES ($1,$2,$3) RETURNING id,name,color', [user.id, body.name, body.color]);
      return rows[0];
    } catch (e) {
      if ((e as { code?: string }).code === '23505') throw new HttpError(409, 'label_exists');
      throw e;
    }
  });
  app.delete('/api/labels/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    await db.query('DELETE FROM labels WHERE id=$1 AND user_id=$2', [id, user.id]);
    return { ok: true };
  });

  // ---- attachments (ciphertext only) ----
  app.post('/api/attachments', { config: { rateLimit: rl(cfg, 60, '1 minute') } }, async (req) => {
    const user = requireUser(req);
    const data = req.body as Buffer;
    if (!Buffer.isBuffer(data) || data.length === 0) throw new HttpError(400, 'empty_attachment');
    if (data.length > cfg.MAX_MESSAGE_BYTES) throw new HttpError(413, 'attachment_too_large');
    // OpenPGP binary packets start with a packet tag byte with the high bit set; refuse obvious plaintext uploads.
    if ((data[0] & 0x80) === 0) throw new HttpError(400, 'not_openpgp_ciphertext');
    const quota = await db.query('SELECT quota_bytes FROM users WHERE id=$1', [user.id]);
    const pending = await db.query(
      `SELECT coalesce(sum(size_bytes),0)::bigint AS s FROM blobs b WHERE owner_user_id=$1
         AND NOT EXISTS (SELECT 1 FROM message_blobs mb WHERE mb.blob_id=b.id)`,
      [user.id],
    );
    if ((await usedBytes(db, user.id)) + Number(pending.rows[0].s) + data.length > Number(quota.rows[0].quota_bytes)) {
      throw new HttpError(413, 'quota_exceeded');
    }
    const storageKey = await ctx.blobs.put(data);
    const { rows } = await db.query('INSERT INTO blobs(owner_user_id,size_bytes,storage_key) VALUES ($1,$2,$3) RETURNING id', [user.id, data.length, storageKey]);
    return { id: rows[0].id, size: data.length };
  });

  app.get('/api/attachments/:id', async (req, reply) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    if (!(await canAccessBlob(db, user.id, id))) throw new HttpError(404, 'not_found');
    const { rows } = await db.query('SELECT storage_key FROM blobs WHERE id=$1', [id]);
    const data = await ctx.blobs.get(rows[0].storage_key);
    reply.header('Content-Type', 'application/octet-stream');
    reply.header('Content-Disposition', 'attachment; filename="encrypted.bin"');
    return reply.send(data);
  });

  // ---- drafts (encrypted client-side to the author's own key) ----
  const draftBody = z.object({ ...encCopy, attachmentIds: z.array(uuid).max(50).default([]) });

  async function saveDraft(userId: string, id: string | null, body: z.infer<typeof draftBody>): Promise<string> {
    for (const b of body.attachmentIds) if (!(await canAccessBlob(db, userId, b))) throw new HttpError(404, 'attachment_not_found');
    const header = b64ToBuf(body.headerEnc);
    const bodyBuf = b64ToBuf(body.bodyEnc);
    const size = header.length + bodyBuf.length + (await blobsSize(db, body.attachmentIds));
    return tx(db, async (c) => {
      let draftId = id;
      if (draftId) {
        const r = await c.query(
          `UPDATE messages SET header_enc=$3, body_enc=$4, key_fingerprint=$5, size_bytes=$6, updated_at=now(), received_at=now()
            WHERE id=$1 AND user_id=$2 AND kind='draft' RETURNING id`,
          [draftId, userId, header, bodyBuf, body.keyFingerprint, size],
        );
        if (!r.rowCount) throw new HttpError(404, 'not_found');
        await c.query('DELETE FROM message_blobs WHERE message_id=$1', [draftId]);
      } else {
        const quota = await c.query('SELECT quota_bytes FROM users WHERE id=$1', [userId]);
        if ((await usedBytes(c, userId)) + size > Number(quota.rows[0].quota_bytes)) throw new HttpError(413, 'quota_exceeded');
        const r = await c.query(
          `INSERT INTO messages(user_id, folder, kind, security, key_fingerprint, header_enc, body_enc, size_bytes, unread)
           VALUES ($1,'drafts','draft','draft',$2,$3,$4,$5,false) RETURNING id`,
          [userId, body.keyFingerprint, header, bodyBuf, size],
        );
        draftId = r.rows[0].id as string;
      }
      await linkBlobs(c, draftId!, body.attachmentIds);
      return draftId!;
    });
  }

  app.post('/api/drafts', async (req) => {
    const user = requireUser(req);
    return { id: await saveDraft(user.id, null, draftBody.parse(req.body)) };
  });
  app.put('/api/drafts/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    return { id: await saveDraft(user.id, id, draftBody.parse(req.body)) };
  });
  app.delete('/api/drafts/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: uuid }).parse(req.params);
    const r = await db.query(`SELECT id FROM messages WHERE id=$1 AND user_id=$2 AND kind='draft'`, [id, user.id]);
    if (!r.rowCount) throw new HttpError(404, 'not_found');
    await purgeMessages(ctx, user.id, [id], false);
    return { ok: true };
  });

  // ---- sending ----
  const sendBody = z.object({
    draftId: uuid.optional(),
    requireTls: z.boolean().default(false),
    inReplyTo: z.string().max(998).regex(/^<[^<>\s]+>$/).optional(),
    references: z.array(z.string().max(998).regex(/^<[^<>\s]+>$/)).max(50).optional(),
    recipients: z.object({
      to: z.array(z.string().max(320)).max(100),
      cc: z.array(z.string().max(320)).max(100).default([]),
      bcc: z.array(z.string().max(320)).max(100).default([]),
    }),
    sentCopy: z.object(encCopy),
    attachmentIds: z.array(uuid).max(50).default([]),
    internal: z.array(z.object({ address: z.string().max(320), ...encCopy })).max(100).default([]),
    external: z
      .object({
        subject: z.string().max(998),
        text: z.string().max(5_000_000),
        html: z.string().max(5_000_000).optional(),
        attachments: z.array(z.object({ id: uuid, key: b64(64), name: z.string().max(255), type: z.string().max(255) })).max(50).default([]),
      })
      .optional(),
  });

  app.post('/api/send', { config: { rateLimit: rl(cfg, 30, '1 minute') } }, async (req) => {
    const user = requireUser(req);
    const body = sendBody.parse(req.body);
    const norm = (list: string[]) =>
      list.map((a) => {
        const n = normalizeAddress(a);
        if (!n) throw new HttpError(400, 'invalid_address', a.slice(0, 100));
        return n;
      });
    const to = norm(body.recipients.to);
    const cc = norm(body.recipients.cc);
    const bcc = norm(body.recipients.bcc);
    const all = [...new Set([...to, ...cc, ...bcc])];
    if (!all.length) throw new HttpError(400, 'no_recipients');
    if (all.length > cfg.MAX_RECIPIENTS_PER_MESSAGE) throw new HttpError(400, 'too_many_recipients');
    const suffix = '@' + cfg.MAIL_DOMAIN;
    const internalAddrs = all.filter((a) => a.endsWith(suffix));
    const externalAddrs = all.filter((a) => !a.endsWith(suffix));

    if (externalAddrs.length && !body.external) throw new HttpError(400, 'external_payload_required');
    // Never accept plaintext when it is not needed for delivery.
    if (!externalAddrs.length && body.external) throw new HttpError(400, 'plaintext_not_allowed_for_e2ee');
    if (!externalAddrs.length && body.requireTls) throw new HttpError(400, 'require_tls_only_for_external');

    const copies = new Map<string, (typeof body.internal)[number]>();
    for (const c of body.internal) {
      const n = normalizeAddress(c.address);
      if (!n || !internalAddrs.includes(n) || copies.has(n)) throw new HttpError(400, 'unexpected_internal_copy');
      copies.set(n, c);
    }

    const me = (await db.query('SELECT display_name, quota_bytes, status FROM users WHERE id=$1', [user.id])).rows[0];
    const myAddress = `${user.username}${suffix}`;
    const myKey = (await db.query(`SELECT fingerprint FROM user_keys WHERE user_id=$1 AND status='active'`, [user.id])).rows[0];
    if (body.sentCopy.keyFingerprint !== myKey.fingerprint) throw new HttpError(409, 'own_key_changed');

    // Sending limits (conservative; no bulk sending).
    const lim = (
      await db.query(
        `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 minute')::int AS per_min,
                coalesce(sum(external) FILTER (WHERE created_at > now() - interval '1 day'),0)::int AS ext_day,
                coalesce(sum(internal) FILTER (WHERE created_at > now() - interval '1 day'),0)::int AS int_day
           FROM send_log WHERE user_id=$1 AND created_at > now() - interval '1 day'`,
        [user.id],
      )
    ).rows[0];
    if (lim.per_min >= cfg.SENDS_PER_MINUTE) throw new HttpError(429, 'send_rate_limited');
    if (lim.ext_day + externalAddrs.length > cfg.EXTERNAL_RECIPIENTS_PER_DAY) throw new HttpError(429, 'daily_external_limit');
    if (lim.int_day + internalAddrs.length > cfg.INTERNAL_RECIPIENTS_PER_DAY) throw new HttpError(429, 'daily_internal_limit');

    for (const b of body.attachmentIds) if (!(await canAccessBlob(db, user.id, b))) throw new HttpError(404, 'attachment_not_found');
    const attSize = await blobsSize(db, body.attachmentIds);

    // Resolve internal recipients and make sure every copy is encrypted to their CURRENT key.
    const recipients: { address: string; userId: string; copy: (typeof body.internal)[number] }[] = [];
    for (const addr of internalAddrs) {
      const local = addr.slice(0, -suffix.length);
      const r = await db.query(
        `SELECT u.id, k.fingerprint FROM users u JOIN user_keys k ON k.user_id=u.id AND k.status='active'
          WHERE u.username=$1 AND u.status='active'`,
        [local],
      );
      if (!r.rowCount) throw new HttpError(400, 'unknown_recipient', addr);
      const copy = copies.get(addr);
      if (!copy) throw new HttpError(400, 'missing_internal_copy', addr);
      if (copy.keyFingerprint !== r.rows[0].fingerprint) throw new HttpError(409, 'recipient_key_changed', addr);
      recipients.push({ address: addr, userId: r.rows[0].id, copy });
    }

    const security = externalAddrs.length ? (body.requireTls ? 'standard_tls_required' : 'standard_tls_optional') : 'e2ee';
    const rfcMessageId = newMessageId(cfg);

    // Build MIME before the transaction: this is the only place the server handles plaintext of outgoing mail.
    let mime: Buffer | null = null;
    if (externalAddrs.length && body.external) {
      if (/[\r\n]/.test(body.external.subject)) throw new HttpError(400, 'invalid_subject');
      const attachments = [];
      for (const a of body.external.attachments) {
        if (!body.attachmentIds.includes(a.id)) throw new HttpError(400, 'attachment_not_in_message');
        const { rows } = await db.query('SELECT storage_key FROM blobs WHERE id=$1', [a.id]);
        let content: Uint8Array;
        try {
          content = await decryptAttachment(await ctx.blobs.get(rows[0].storage_key), a.key);
        } catch {
          throw new HttpError(400, 'attachment_key_invalid');
        }
        attachments.push({ filename: sanitizeFilename(a.name), contentType: /^[\w.+-]+\/[\w.+-]+$/.test(a.type) ? a.type : 'application/octet-stream', content: Buffer.from(content) });
      }
      mime = await buildMime(cfg, {
        from: { name: (me.display_name as string).replace(/[\r\n"]/g, ''), address: myAddress },
        to,
        cc,
        subject: body.external.subject,
        text: body.external.text,
        html: body.external.html,
        attachments,
        messageId: rfcMessageId,
        inReplyTo: body.inReplyTo,
        references: body.references,
      });
      if (mime.length > cfg.MAX_MESSAGE_BYTES * 1.4) throw new HttpError(413, 'message_too_large');
    }

    const result = await tx(db, async (c) => {
      const sentHeader = b64ToBuf(body.sentCopy.headerEnc);
      const sentBody = b64ToBuf(body.sentCopy.bodyEnc);
      const sentSize = sentHeader.length + sentBody.length + attSize;
      if ((await usedBytes(c, user.id)) + sentSize > Number(me.quota_bytes)) throw new HttpError(413, 'quota_exceeded');
      const sent = await c.query(
        `INSERT INTO messages(user_id, folder, kind, security, key_fingerprint, header_enc, body_enc, size_bytes, unread,
                              sender_address, message_id, in_reply_to)
         VALUES ($1,'sent',$2,$3,$4,$5,$6,$7,false,$8,$9,$10) RETURNING id`,
        [user.id, externalAddrs.length ? 'external_out' : 'internal_out', security, body.sentCopy.keyFingerprint, sentHeader, sentBody, sentSize, myAddress, rfcMessageId, body.inReplyTo ?? null],
      );
      const sentId = sent.rows[0].id as string;
      await linkBlobs(c, sentId, body.attachmentIds);

      for (const r of recipients) {
        const h = b64ToBuf(r.copy.headerEnc);
        const b = b64ToBuf(r.copy.bodyEnc);
        const size = h.length + b.length + attSize;
        const q = await c.query('SELECT quota_bytes FROM users WHERE id=$1', [r.userId]);
        if ((await usedBytes(c, r.userId)) + size > Number(q.rows[0].quota_bytes)) throw new HttpError(413, 'recipient_over_quota', r.address);
        const ins = await c.query(
          `INSERT INTO messages(user_id, folder, kind, security, key_fingerprint, header_enc, body_enc, size_bytes, unread,
                                sender_address, message_id, in_reply_to)
           VALUES ($1,'inbox','internal_in',$2,$3,$4,$5,$6,true,$7,$8,$9) RETURNING id`,
          [r.userId, security, r.copy.keyFingerprint, h, b, size, myAddress, rfcMessageId, body.inReplyTo ?? null],
        );
        await linkBlobs(c, ins.rows[0].id, body.attachmentIds);
      }

      let queueId: string | null = null;
      if (mime) {
        queueId = await enqueueOutbound(cfg, c, {
          userId: user.id,
          messageId: sentId,
          kind: 'user',
          requireTls: body.requireTls,
          rfcMessageId,
          recipients: externalAddrs,
          mime,
        });
      }
      if (body.draftId) {
        await c.query(`DELETE FROM messages WHERE id=$1 AND user_id=$2 AND kind='draft'`, [body.draftId, user.id]);
      }
      await c.query('INSERT INTO send_log(user_id, external, internal) VALUES ($1,$2,$3)', [user.id, externalAddrs.length, internalAddrs.length]);
      return { id: sentId, messageId: rfcMessageId, queueId, security };
    });
    mime?.fill(0);
    return result;
  });

  app.get('/api/quota', async (req) => {
    const user = requireUser(req);
    const q = await db.query('SELECT quota_bytes FROM users WHERE id=$1', [user.id]);
    return { used: await usedBytes(db, user.id), quota: Number(q.rows[0].quota_bytes) };
  });
}

async function updateMessages(
  db: Queryable,
  userId: string,
  ids: string[],
  body: { unread?: boolean; starred?: boolean; folder?: (typeof USER_FOLDERS)[number] | 'restore' },
) {
  if (body.unread !== undefined) {
    await db.query('UPDATE messages SET unread=$3, updated_at=now() WHERE user_id=$1 AND id = ANY($2::uuid[])', [userId, ids, body.unread]);
  }
  if (body.starred !== undefined) {
    await db.query('UPDATE messages SET starred=$3, updated_at=now() WHERE user_id=$1 AND id = ANY($2::uuid[])', [userId, ids, body.starred]);
  }
  if (body.folder === 'restore') {
    await db.query(
      `UPDATE messages SET folder = coalesce(prev_folder, CASE kind WHEN 'draft' THEN 'drafts' WHEN 'internal_out' THEN 'sent' WHEN 'external_out' THEN 'sent' ELSE 'inbox' END),
              prev_folder = NULL, folder_changed_at = now(), updated_at = now()
        WHERE user_id=$1 AND id = ANY($2::uuid[]) AND folder IN ('trash','spam')`,
      [userId, ids],
    );
  } else if (body.folder) {
    // Sent mail and drafts may only go to trash (and back via restore); received mail can move freely.
    await db.query(
      `UPDATE messages SET prev_folder = CASE WHEN $3 IN ('trash','spam') AND folder NOT IN ('trash','spam') THEN folder ELSE prev_folder END,
              folder = $3, folder_changed_at = now(), updated_at = now()
        WHERE user_id=$1 AND id = ANY($2::uuid[]) AND folder <> $3
          AND (kind IN ('internal_in','external_in','system') OR $3 = 'trash')`,
      [userId, ids, body.folder],
    );
  }
}
