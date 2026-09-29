import { SMTPServer } from 'smtp-server';
import os from 'node:os';
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';
import { FsBlobStore } from './blobstore.js';
import { buildApp, type Ctx } from './app.js';
import { InboundError, processInbound, resolveRecipient } from './inbound.js';
import { lookupServer } from './lookup.js';
import { runOnce, smtpRelay } from './worker.js';
import { runRetention } from './retention.js';
import { deleteAccount } from './routes/settings.js';

function makeCtx(poolSize = 10): Ctx {
  const cfg = loadConfig();
  return { cfg, db: createPool(cfg.DATABASE_URL, poolSize), blobs: new FsBlobStore(cfg.BLOB_DIR) };
}

async function api() {
  const ctx = makeCtx();
  await migrate(ctx.db);
  const app = await buildApp(ctx, { serveStatic: true, log: true });
  await app.listen({ host: ctx.cfg.HTTP_HOST, port: ctx.cfg.HTTP_PORT });
  console.log(`[api] listening on ${ctx.cfg.HTTP_HOST}:${ctx.cfg.HTTP_PORT}`);
}

async function mx() {
  const ctx = makeCtx();
  const max = ctx.cfg.MAX_MESSAGE_BYTES + 1024 * 1024;
  const lmtp = new SMTPServer({
    lmtp: true,
    logger: false,
    authOptional: true,
    disabledCommands: ['AUTH', 'STARTTLS'],
    size: max,
    banner: 'VoidMail inbound bridge',
    async onRcptTo(address, _session, cb) {
      try {
        const r = await resolveRecipient(ctx, address.address);
        cb(r ? undefined : Object.assign(new Error('5.1.1 No such user'), { responseCode: 550 }));
      } catch {
        cb(Object.assign(new Error('4.3.0 Temporary failure'), { responseCode: 451 }));
      }
    },
    onData(stream, session, cb) {
      const chunks: Buffer[] = [];
      let size = 0;
      stream.on('data', (c: Buffer) => {
        size += c.length;
        if (size <= max) chunks.push(c);
      });
      stream.on('end', async () => {
        const rcpts = session.envelope.rcptTo.map((r) => r.address);
        if (size > max || (stream as unknown as { sizeExceeded?: boolean }).sizeExceeded) {
          return cb(Object.assign(new Error('5.3.4 Message too big'), { responseCode: 552 }));
        }
        const raw = Buffer.concat(chunks);
        try {
          const results = await processInbound(ctx, raw, rcpts);
          cb(null, results.map((r) => (r instanceof InboundError ? Object.assign(new Error(r.message), { responseCode: r.responseCode }) : r)) as never);
        } catch (e) {
          console.error('[mx] error:', (e as Error).message);
          cb(Object.assign(new Error('4.3.0 Temporary failure'), { responseCode: 451 }));
        } finally {
          raw.fill(0);
        }
      });
    },
  });
  lmtp.on('error', (e) => console.error('[mx] lmtp error:', e.message));
  lmtp.listen(ctx.cfg.LMTP_PORT, ctx.cfg.LMTP_HOST, () => console.log(`[mx] LMTP on ${ctx.cfg.LMTP_HOST}:${ctx.cfg.LMTP_PORT}`));
  lookupServer(ctx).listen(ctx.cfg.LOOKUP_PORT, ctx.cfg.LMTP_HOST, () => console.log(`[mx] recipient lookup on ${ctx.cfg.LMTP_HOST}:${ctx.cfg.LOOKUP_PORT}`));
}

async function worker() {
  const ctx = makeCtx(4);
  const relay = smtpRelay(ctx);
  let lastRetention = 0;
  console.log('[worker] started');
  for (;;) {
    try {
      const n = await runOnce(ctx, relay);
      if (Date.now() - lastRetention > 3600_000) {
        const report = await runRetention(ctx);
        console.log('[worker] retention', JSON.stringify(report));
        lastRetention = Date.now();
      }
      if (n === 0) await new Promise((r) => setTimeout(r, 2000));
    } catch (e) {
      console.error('[worker] loop error:', (e as Error).message);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

async function admin(args: string[]) {
  const ctx = makeCtx(2);
  const actor = process.env.ADMIN_ACTOR || os.userInfo().username;
  const audit = (action: string, target: string | null) =>
    ctx.db.query('INSERT INTO admin_audit(actor, action, target) VALUES ($1,$2,$3)', [actor, action, target]);
  const [cmd, arg, arg2] = args;
  const userId = async (username: string) => {
    const r = await ctx.db.query('SELECT id FROM users WHERE username=$1', [username]);
    if (!r.rowCount) throw new Error('no such user');
    return r.rows[0].id as string;
  };
  switch (cmd) {
    case 'users': {
      const { rows } = await ctx.db.query(
        `SELECT u.username, u.status, u.created_at, u.quota_bytes, coalesce(sum(m.size_bytes),0)::bigint AS used, count(m.id)::int AS messages
           FROM users u LEFT JOIN messages m ON m.user_id = u.id GROUP BY u.id ORDER BY u.created_at`,
      );
      console.table(rows);
      await audit('list_users', null);
      break;
    }
    case 'suspend':
    case 'unsuspend': {
      const id = await userId(arg);
      await ctx.db.query('UPDATE users SET status=$2 WHERE id=$1', [id, cmd === 'suspend' ? 'suspended' : 'active']);
      if (cmd === 'suspend') {
        await ctx.db.query('DELETE FROM sessions WHERE user_id=$1', [id]);
        await ctx.db.query(`UPDATE outbound_queue SET status='cancelled', payload_enc=NULL WHERE user_id=$1 AND status IN ('queued','sending')`, [id]);
      }
      await audit(cmd, arg);
      console.log(`${cmd}ed ${arg}`);
      break;
    }
    case 'revoke-sessions': {
      const id = await userId(arg);
      const r = await ctx.db.query('DELETE FROM sessions WHERE user_id=$1', [id]);
      await audit('revoke_sessions', arg);
      console.log(`revoked ${r.rowCount} sessions`);
      break;
    }
    case 'set-quota': {
      const id = await userId(arg);
      const bytes = Number(arg2);
      if (!Number.isFinite(bytes) || bytes < 0) throw new Error('usage: set-quota <username> <bytes>');
      await ctx.db.query('UPDATE users SET quota_bytes=$2 WHERE id=$1', [id, bytes]);
      await audit('set_quota', `${arg}=${bytes}`);
      break;
    }
    case 'delete-user': {
      if (arg2 !== '--confirm') throw new Error('usage: delete-user <username> --confirm');
      await deleteAccount(ctx, await userId(arg));
      await audit('delete_user', arg);
      console.log('deleted');
      break;
    }
    case 'queue': {
      const { rows } = await ctx.db.query(
        `SELECT status, count(*)::int AS n, min(created_at) AS oldest FROM outbound_queue GROUP BY status`,
      );
      console.table(rows);
      await audit('queue_stats', null);
      break;
    }
    case 'audit': {
      console.table((await ctx.db.query('SELECT actor, action, target, created_at FROM admin_audit ORDER BY id DESC LIMIT 50')).rows);
      break;
    }
    default:
      console.log(`VoidMail admin CLI (no command can read or decrypt mail)
  users                         list accounts with storage metadata
  suspend|unsuspend <username>  suspend (also revokes sessions, cancels queued mail)
  revoke-sessions <username>
  set-quota <username> <bytes>
  delete-user <username> --confirm
  queue                         outbound queue statistics
  audit                         last 50 admin actions`);
  }
  await ctx.db.end();
}

const [cmd, ...rest] = process.argv.slice(2);
const run: Record<string, () => Promise<void>> = {
  api,
  mx,
  worker,
  migrate: async () => {
    const ctx = makeCtx(1);
    console.log('[migrate] applied:', (await migrate(ctx.db)).join(', ') || 'none');
    await ctx.db.end();
  },
  retention: async () => {
    const ctx = makeCtx(1);
    console.log(JSON.stringify(await runRetention(ctx)));
    await ctx.db.end();
  },
  admin: () => admin(rest),
};
if (!run[cmd]) {
  console.error('usage: main.js <api|mx|worker|migrate|retention|admin>');
  process.exit(2);
}
run[cmd]().catch((e) => {
  console.error(`[${cmd}] fatal:`, (e as Error).message);
  process.exit(1);
});
