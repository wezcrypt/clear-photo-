import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { type Ctx, HttpError, clearSessionCookie, logSecurityEvent, requireUser } from '../app.js';
import { tx } from '../db.js';
import { b64ToBuf, hmac, verifySecret } from '../security.js';
import { normalizeAddress } from '../../shared/mail.js';
import { deleteOrphanBlobs } from '../retention.js';
import { rl } from '../ratelimits.js';

export async function deleteAccount(ctx: Ctx, userId: string): Promise<void> {
  const { db, cfg } = ctx;
  await tx(db, async (c) => {
    const u = await c.query('SELECT username FROM users WHERE id=$1 FOR UPDATE', [userId]);
    if (!u.rowCount) return;
    // Cancel pending outbound deliveries and drop their payloads.
    await c.query(
      `UPDATE outbound_queue SET status='cancelled', payload_enc=NULL, updated_at=now() WHERE user_id=$1 AND status IN ('queued','sending')`,
      [userId],
    );
    await c.query(`UPDATE outbound_recipients SET status='cancelled' WHERE queue_id IN (SELECT id FROM outbound_queue WHERE user_id=$1) AND status='queued'`, [userId]);
    await c.query('DELETE FROM outbound_queue WHERE user_id=$1', [userId]);
    // Keep a keyed hash of the username so the address can never be re-registered by someone else.
    await c.query('INSERT INTO username_tombstones(username_hash) VALUES ($1) ON CONFLICT DO NOTHING', [hmac(cfg.keys.app, 'tomb:' + u.rows[0].username)]);
    // Cascades: keys, sessions, messages, labels, message_blobs, codes, events, send_log.
    await c.query('DELETE FROM users WHERE id=$1', [userId]);
  });
  // Blobs are shared between sender and internal recipients: delete only those no remaining message references.
  await deleteOrphanBlobs(ctx, db, null, 0);
}

export async function settingsRoutes(app: FastifyInstance, ctx: Ctx): Promise<void> {
  const { db, cfg } = ctx;

  app.patch('/api/settings', async (req) => {
    const user = requireUser(req);
    const body = z
      .object({
        displayName: z.string().max(64).optional(),
        locale: z.enum(['en', 'ar']).optional(),
        theme: z.enum(['system', 'dark', 'light']).optional(),
        remoteImages: z.enum(['ask', 'never']).optional(),
        recoveryEmail: z.string().max(254).nullable().optional(),
      })
      .parse(req.body);
    if (body.displayName !== undefined && /[\r\n<>"]/.test(body.displayName)) throw new HttpError(400, 'invalid_display_name');
    let recoveryEmail: string | null | undefined = undefined;
    if (body.recoveryEmail !== undefined) {
      recoveryEmail = body.recoveryEmail ? normalizeAddress(body.recoveryEmail) : null;
      if (body.recoveryEmail && !recoveryEmail) throw new HttpError(400, 'invalid_recovery_email');
      if (recoveryEmail?.endsWith('@' + cfg.MAIL_DOMAIN)) throw new HttpError(400, 'recovery_email_must_be_external');
    }
    await db.query(
      `UPDATE users SET display_name = coalesce($2, display_name), locale = coalesce($3, locale), theme = coalesce($4, theme),
              remote_images = coalesce($5, remote_images),
              recovery_email = CASE WHEN $6::boolean THEN $7 ELSE recovery_email END
        WHERE id=$1`,
      [user.id, body.displayName?.trim() ?? null, body.locale ?? null, body.theme ?? null, body.remoteImages ?? null, recoveryEmail !== undefined, recoveryEmail ?? null],
    );
    if (recoveryEmail !== undefined) await logSecurityEvent(ctx, user.id, recoveryEmail ? 'recovery_email_set' : 'recovery_email_removed', req.ip);
    return { ok: true };
  });

  /** Account metadata export. Message contents are exported client-side after decryption. */
  app.get('/api/export/account', async (req) => {
    const user = requireUser(req);
    const u = (
      await db.query(
        'SELECT username, display_name, locale, theme, remote_images, recovery_email, totp_enabled, quota_bytes, created_at FROM users WHERE id=$1',
        [user.id],
      )
    ).rows[0];
    const keys = (await db.query('SELECT fingerprint, status, public_key, created_at, retired_at FROM user_keys WHERE user_id=$1', [user.id])).rows;
    const labels = (await db.query('SELECT id, name, color, created_at FROM labels WHERE user_id=$1', [user.id])).rows;
    const sessions = (await db.query('SELECT created_at, last_seen_at, user_agent FROM sessions WHERE user_id=$1', [user.id])).rows;
    const events = (await db.query('SELECT type, ip_prefix, created_at FROM security_events WHERE user_id=$1 ORDER BY created_at DESC', [user.id])).rows;
    const counts = (await db.query('SELECT folder, count(*)::int AS n, sum(size_bytes)::bigint AS bytes FROM messages WHERE user_id=$1 GROUP BY folder', [user.id])).rows;
    return {
      exportedAt: new Date().toISOString(),
      account: { ...u, address: `${u.username}@${cfg.MAIL_DOMAIN}` },
      publicKeys: keys,
      labels,
      sessions,
      securityEvents: events,
      storage: counts.map((c) => ({ folder: c.folder, messages: c.n, bytes: Number(c.bytes) })),
    };
  });

  app.post('/api/account/delete', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req, reply) => {
    const user = requireUser(req);
    const body = z.object({ authKey: z.string().max(64), confirm: z.literal('DELETE') }).parse(req.body);
    const { rows } = await db.query('SELECT auth_hash FROM users WHERE id=$1', [user.id]);
    if (!(await verifySecret(cfg, rows[0].auth_hash, b64ToBuf(body.authKey)))) throw new HttpError(401, 'invalid_credentials');
    await deleteAccount(ctx, user.id);
    clearSessionCookie(ctx, reply);
    return { ok: true };
  });
}
