import type { Ctx } from './app.js';
import type { Queryable } from './db.js';

/** Deletes blobs (rows + stored objects) that no message references any more. */
export async function deleteOrphanBlobs(ctx: Ctx, db: Queryable, candidateIds: string[] | null, minAgeHours = 0): Promise<number> {
  const params: unknown[] = [minAgeHours];
  let filter = '';
  if (candidateIds) {
    if (!candidateIds.length) return 0;
    params.push(candidateIds);
    filter = 'AND b.id = ANY($2::uuid[])';
  }
  const { rows } = await db.query(
    `DELETE FROM blobs b
      WHERE NOT EXISTS (SELECT 1 FROM message_blobs mb WHERE mb.blob_id = b.id)
        AND b.created_at < now() - make_interval(hours => $1::int) ${filter}
      RETURNING storage_key`,
    params,
  );
  for (const r of rows) await ctx.blobs.delete(r.storage_key);
  return rows.length;
}

/**
 * Permanently deletes a user's messages. With requireTrash, only messages already in Trash/Spam (or drafts) are removed,
 * so a single mistaken click in the inbox cannot destroy mail.
 */
export async function purgeMessages(ctx: Ctx, userId: string, ids: string[], requireTrash: boolean): Promise<number> {
  const { rows } = await ctx.db.query(
    `WITH del AS (
        DELETE FROM messages WHERE user_id=$1 AND id = ANY($2::uuid[])
          ${requireTrash ? "AND (folder IN ('trash','spam') OR kind = 'draft')" : ''}
        RETURNING id)
     SELECT id FROM del`,
    [userId, ids],
  );
  // message_blobs rows were removed by ON DELETE CASCADE; now drop blobs nobody references.
  // Unattached uploads younger than an hour may belong to a draft being composed, so they are kept.
  await deleteOrphanBlobs(ctx, ctx.db, null, 1);
  return rows.length;
}

export interface RetentionReport {
  trashPurged: number;
  sessions: number;
  challenges: number;
  resets: number;
  securityEvents: number;
  sendLog: number;
  queueRows: number;
  orphanBlobs: number;
}

export async function runRetention(ctx: Ctx): Promise<RetentionReport> {
  const { db, cfg } = ctx;
  const trash = await db.query(
    `DELETE FROM messages WHERE folder IN ('trash','spam') AND folder_changed_at < now() - make_interval(days => $1::int) RETURNING id`,
    [cfg.TRASH_RETENTION_DAYS],
  );
  const sessions = await db.query(`DELETE FROM sessions WHERE expires_at < now() OR last_seen_at < now() - interval '7 days'`);
  const challenges = await db.query('DELETE FROM login_challenges WHERE expires_at < now()');
  const resets = await db.query(`DELETE FROM password_resets WHERE expires_at < now() - interval '1 day'`);
  const events = await db.query(`DELETE FROM security_events WHERE created_at < now() - make_interval(days => $1::int)`, [
    cfg.SECURITY_EVENT_RETENTION_DAYS,
  ]);
  const sendLog = await db.query(`DELETE FROM send_log WHERE created_at < now() - interval '2 days'`);
  // Delivery status metadata is kept 30 days; payloads are already deleted when relayed.
  const queue = await db.query(
    `DELETE FROM outbound_queue WHERE status IN ('relayed','failed','cancelled') AND updated_at < now() - interval '30 days'`,
  );
  // Safety net: a failed/cancelled row must never keep a payload.
  await db.query(`UPDATE outbound_queue SET payload_enc = NULL WHERE status IN ('relayed','failed','cancelled') AND payload_enc IS NOT NULL`);
  const orphans = await deleteOrphanBlobs(ctx, db, null, 24);
  return {
    trashPurged: trash.rowCount ?? 0,
    sessions: sessions.rowCount ?? 0,
    challenges: challenges.rowCount ?? 0,
    resets: resets.rowCount ?? 0,
    securityEvents: events.rowCount ?? 0,
    sendLog: sendLog.rowCount ?? 0,
    queueRows: queue.rowCount ?? 0,
    orphanBlobs: orphans,
  };
}
