import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { generateSecret, generateURI, verify as verifyTotp } from 'otplib';
import { randomBytes } from 'node:crypto';
import {
  type Ctx,
  HttpError,
  clearSessionCookie,
  cookieName,
  createSession,
  csrfFor,
  logSecurityEvent,
  requireUser,
} from '../app.js';
import { tx } from '../db.js';
import {
  b64ToBuf,
  dummyVerify,
  hashSecret,
  hmac,
  openServer,
  randomToken,
  sealServer,
  sha256,
  verifySecret,
} from '../security.js';
import { isValidUsername, normalizeAddress } from '../../shared/mail.js';
import { readPublicKey } from '../../shared/crypto.js';
import { enqueueSystemEmail } from '../outbound.js';
import { rl } from '../ratelimits.js';

const b64 = (max: number) => z.string().max(max).regex(/^[A-Za-z0-9+/]*={0,2}$/);
const secret32 = b64(64).refine((s) => b64ToBuf(s).length === 32, 'must be 32 bytes');
const kdfParams = z.object({
  alg: z.literal('argon2id'),
  m: z.number().int().min(19456).max(1048576),
  t: z.number().int().min(2).max(20),
  p: z.number().int().min(1).max(8),
  v: z.literal(1),
});
const wrapped = b64(512);
const armored = (max: number) => z.string().max(max).startsWith('-----BEGIN PGP');

const credentialSet = {
  salt: b64(64).refine((s) => b64ToBuf(s).length === 16, 'salt must be 16 bytes'),
  kdfParams,
  authKey: secret32,
  mkWrappedPassword: wrapped,
};
const recoverySet = { mkWrappedRecovery: wrapped, recoveryAuth: secret32 };
const keySet = {
  publicKey: armored(20000),
  privateKeyEnc: armored(40000),
  fingerprint: z.string().regex(/^[0-9a-f]{40,64}$/),
  revocationCertEnc: b64(20000).optional(),
};

function usernameOf(input: string): string {
  return input.trim().toLowerCase().replace(/@.*$/, '');
}

/** Checks that an uploaded public key is well-formed, matches the claimed fingerprint and belongs to the address. */
async function checkPublicKey(armoredKey: string, fingerprint: string, address: string): Promise<void> {
  let key;
  try {
    key = await readPublicKey(armoredKey);
  } catch {
    throw new HttpError(400, 'invalid_public_key');
  }
  if (key.isPrivate()) throw new HttpError(400, 'invalid_public_key');
  if (key.getFingerprint() !== fingerprint) throw new HttpError(400, 'fingerprint_mismatch');
  const emails = key.getUserIDs().map((u) => (/<([^>]+)>/.exec(u)?.[1] ?? u).toLowerCase());
  if (!emails.includes(address)) throw new HttpError(400, 'key_address_mismatch');
  await key.getEncryptionKey().catch(() => {
    throw new HttpError(400, 'invalid_public_key');
  });
}

export async function sessionPayload(ctx: Ctx, userId: string, csrf: string) {
  const u = (
    await ctx.db.query(
      `SELECT id, username, display_name, locale, theme, remote_images, totp_enabled, recovery_email,
              mk_wrapped_password, (mk_wrapped_recovery IS NOT NULL) AS has_recovery, quota_bytes, vault_version
         FROM users WHERE id = $1`,
      [userId],
    )
  ).rows[0];
  const keys = (
    await ctx.db.query(
      `SELECT id, fingerprint, status, public_key, private_key_enc, created_at
         FROM user_keys WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    )
  ).rows;
  return {
    user: {
      id: u.id,
      username: u.username,
      address: `${u.username}@${ctx.cfg.MAIL_DOMAIN}`,
      displayName: u.display_name,
      locale: u.locale,
      theme: u.theme,
      remoteImages: u.remote_images,
      totpEnabled: u.totp_enabled,
      recoveryEmail: u.recovery_email,
      hasRecoveryKey: u.has_recovery,
      quotaBytes: Number(u.quota_bytes),
    },
    csrf,
    domain: ctx.cfg.MAIL_DOMAIN,
    mkWrappedPassword: Buffer.from(u.mk_wrapped_password).toString('base64'),
    keys: keys.map((k) => ({
      id: k.id,
      fingerprint: k.fingerprint,
      status: k.status,
      publicKey: k.public_key,
      privateKeyEnc: k.private_key_enc,
      createdAt: k.created_at,
    })),
  };
}

async function startSession(ctx: Ctx, req: FastifyRequest, reply: FastifyReply, userId: string) {
  const hash = await createSession(ctx, reply, userId, req.headers['user-agent']);
  return sessionPayload(ctx, userId, csrfFor(ctx.cfg, hash));
}

async function checkTotp(ctx: Ctx, userId: string, code: string): Promise<boolean> {
  const { rows } = await ctx.db.query('SELECT totp_secret_enc, totp_last_step FROM users WHERE id = $1', [userId]);
  if (!rows[0]?.totp_secret_enc) return false;
  const secret = (await openServer(ctx.cfg.keys.totp, rows[0].totp_secret_enc, 'totp:' + userId)).toString('utf8');
  const res = await verifyTotp({
    secret,
    token: code,
    epochTolerance: 30,
    afterTimeStep: rows[0].totp_last_step != null ? Number(rows[0].totp_last_step) : undefined,
  }).catch(() => ({ valid: false as const }));
  if (!res.valid) return false;
  // Replay protection: a code's time step can be used once.
  const upd = await ctx.db.query(
    'UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)',
    [userId, (res as { timeStep: number }).timeStep],
  );
  return upd.rowCount === 1;
}

async function useRecoveryCode(ctx: Ctx, userId: string, code: string): Promise<boolean> {
  const normalized = code.replace(/[\s-]/g, '').toLowerCase();
  const upd = await ctx.db.query(
    'UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL',
    [userId, sha256('rc:' + normalized)],
  );
  return upd.rowCount === 1;
}

async function makeRecoveryCodes(ctx: Ctx, userId: string, db = ctx.db as import('../db.js').Queryable): Promise<string[]> {
  await db.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
  const codes: string[] = [];
  for (let i = 0; i < 10; i++) {
    const raw = randomBytes(8).toString('hex'); // 64 bits
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12)}`);
    await db.query('INSERT INTO recovery_codes(user_id, code_hash) VALUES ($1,$2)', [userId, sha256('rc:' + raw)]);
  }
  return codes;
}

async function registerFailure(ctx: Ctx, userId: string): Promise<void> {
  // Progressive per-account throttle: after 5 failures, lock for 2^(n-5) minutes (max 60).
  await ctx.db.query(
    `UPDATE users SET failed_logins = failed_logins + 1,
       login_locked_until = CASE WHEN failed_logins + 1 >= 5
         THEN now() + make_interval(mins => LEAST(60, power(2, failed_logins + 1 - 5)::int)) ELSE login_locked_until END
     WHERE id = $1`,
    [userId],
  );
}

async function verifyAuthKey(ctx: Ctx, userId: string, authKey: string): Promise<boolean> {
  const { rows } = await ctx.db.query('SELECT auth_hash FROM users WHERE id = $1', [userId]);
  return rows.length > 0 && verifySecret(ctx.cfg, rows[0].auth_hash, b64ToBuf(authKey));
}

export async function authRoutes(app: FastifyInstance, ctx: Ctx): Promise<void> {
  const { cfg, db } = ctx;
  const domain = cfg.MAIL_DOMAIN;

  app.post('/api/auth/prelogin', { config: { rateLimit: rl(cfg, 30, '1 minute') } }, async (req) => {
    const { username } = z.object({ username: z.string().max(320) }).parse(req.body);
    const name = usernameOf(username);
    const { rows } = await db.query('SELECT kdf_salt, kdf_params FROM users WHERE username = $1', [name]);
    if (rows.length) return { salt: Buffer.from(rows[0].kdf_salt).toString('base64'), kdfParams: rows[0].kdf_params };
    // Deterministic decoy so this endpoint does not reveal whether the account exists.
    return {
      salt: hmac(cfg.keys.app, 'decoy-salt:' + name).subarray(0, 16).toString('base64'),
      kdfParams: { alg: 'argon2id', m: cfg.CLIENT_KDF_M, t: cfg.CLIENT_KDF_T, p: 1, v: 1 },
    };
  });

  app.get('/api/auth/params', async () => ({
    kdfParams: { alg: 'argon2id', m: cfg.CLIENT_KDF_M, t: cfg.CLIENT_KDF_T, p: 1, v: 1 },
    domain,
    registrationOpen: cfg.REGISTRATION_OPEN === 'true',
  }));

  app.post('/api/auth/register', { config: { rateLimit: rl(cfg, 5, '1 hour') } }, async (req, reply) => {
    if (cfg.REGISTRATION_OPEN !== 'true') throw new HttpError(403, 'registration_closed');
    const body = z
      .object({
        username: z.string(),
        displayName: z.string().max(64).default(''),
        ...credentialSet,
        ...recoverySet,
        ...keySet,
        recoveryEmail: z.string().max(254).optional().nullable(),
      })
      .parse(req.body);
    const username = body.username.trim().toLowerCase();
    if (!isValidUsername(username)) throw new HttpError(400, 'invalid_username');
    if (['postmaster', 'abuse', 'admin', 'root', 'bounces', 'no-reply', 'noreply', 'hostmaster', 'security', 'mailer-daemon'].includes(username)) {
      throw new HttpError(409, 'username_taken');
    }
    const recoveryEmail = body.recoveryEmail ? normalizeAddress(body.recoveryEmail) : null;
    if (body.recoveryEmail && !recoveryEmail) throw new HttpError(400, 'invalid_recovery_email');
    if (recoveryEmail?.endsWith('@' + domain)) throw new HttpError(400, 'recovery_email_must_be_external');
    if (/[\r\n<>"]/.test(body.displayName)) throw new HttpError(400, 'invalid_display_name');
    await checkPublicKey(body.publicKey, body.fingerprint, `${username}@${domain}`);

    const tomb = await db.query('SELECT 1 FROM username_tombstones WHERE username_hash = $1', [hmac(cfg.keys.app, 'tomb:' + username)]);
    if (tomb.rowCount) throw new HttpError(409, 'username_taken');

    const authHash = await hashSecret(cfg, b64ToBuf(body.authKey));
    const recoveryHash = await hashSecret(cfg, b64ToBuf(body.recoveryAuth));
    let userId: string;
    try {
      userId = await tx(db, async (c) => {
        const u = await c.query(
          `INSERT INTO users(username, display_name, kdf_salt, kdf_params, auth_hash, mk_wrapped_password,
                             mk_wrapped_recovery, recovery_auth_hash, recovery_email, quota_bytes)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
          [username, body.displayName.trim(), b64ToBuf(body.salt), body.kdfParams, authHash, b64ToBuf(body.mkWrappedPassword),
            b64ToBuf(body.mkWrappedRecovery), recoveryHash, recoveryEmail, cfg.DEFAULT_QUOTA_BYTES],
        );
        const id = u.rows[0].id as string;
        await c.query(
          `INSERT INTO user_keys(user_id, fingerprint, public_key, private_key_enc, revocation_cert_enc, status)
           VALUES ($1,$2,$3,$4,$5,'active')`,
          [id, body.fingerprint, body.publicKey, body.privateKeyEnc, body.revocationCertEnc ? b64ToBuf(body.revocationCertEnc) : null],
        );
        return id;
      });
    } catch (e) {
      if ((e as { code?: string }).code === '23505') throw new HttpError(409, 'username_taken');
      throw e;
    }
    await logSecurityEvent(ctx, userId, 'register', req.ip);
    return startSession(ctx, req, reply, userId);
  });

  app.post('/api/auth/login', { config: { rateLimit: rl(cfg, 10, '1 minute') } }, async (req, reply) => {
    const body = z.object({ username: z.string().max(320), authKey: secret32 }).parse(req.body);
    const name = usernameOf(body.username);
    const { rows } = await db.query(
      'SELECT id, auth_hash, status, totp_enabled, login_locked_until FROM users WHERE username = $1',
      [name],
    );
    const u = rows[0];
    if (!u) {
      await dummyVerify(cfg);
      throw new HttpError(401, 'invalid_credentials');
    }
    if (u.login_locked_until && new Date(u.login_locked_until) > new Date()) {
      await logSecurityEvent(ctx, u.id, 'login_throttled', req.ip);
      throw new HttpError(429, 'too_many_attempts');
    }
    const ok = await verifySecret(cfg, u.auth_hash, b64ToBuf(body.authKey));
    if (!ok) {
      await registerFailure(ctx, u.id);
      await logSecurityEvent(ctx, u.id, 'login_failed', req.ip);
      throw new HttpError(401, 'invalid_credentials');
    }
    if (u.status !== 'active') throw new HttpError(403, 'account_suspended');
    if (u.totp_enabled) {
      const challenge = randomToken(32);
      await db.query(
        `INSERT INTO login_challenges(id_hash, user_id, purpose, expires_at) VALUES ($1,$2,'totp', now() + interval '5 minutes')`,
        [sha256(challenge), u.id],
      );
      return { mfaRequired: true, challenge };
    }
    await db.query('UPDATE users SET failed_logins = 0, login_locked_until = NULL WHERE id = $1', [u.id]);
    await logSecurityEvent(ctx, u.id, 'login', req.ip);
    return startSession(ctx, req, reply, u.id);
  });

  app.post('/api/auth/login/totp', { config: { rateLimit: rl(cfg, 10, '1 minute') } }, async (req, reply) => {
    const body = z.object({ challenge: z.string().max(64), code: z.string().min(6).max(24) }).parse(req.body);
    const hash = sha256(body.challenge);
    const { rows } = await db.query(
      `UPDATE login_challenges SET attempts = attempts + 1
        WHERE id_hash = $1 AND purpose = 'totp' AND expires_at > now() AND attempts < 5
        RETURNING user_id`,
      [hash],
    );
    if (!rows.length) throw new HttpError(401, 'challenge_expired');
    const userId = rows[0].user_id as string;
    const code = body.code.trim();
    const ok = /^\d{6}$/.test(code) ? await checkTotp(ctx, userId, code) : await useRecoveryCode(ctx, userId, code);
    if (!ok) {
      await registerFailure(ctx, userId);
      await logSecurityEvent(ctx, userId, 'totp_failed', req.ip);
      throw new HttpError(401, 'invalid_code');
    }
    await db.query('DELETE FROM login_challenges WHERE id_hash = $1', [hash]);
    await db.query('UPDATE users SET failed_logins = 0, login_locked_until = NULL WHERE id = $1', [userId]);
    await logSecurityEvent(ctx, userId, /^\d{6}$/.test(code) ? 'login' : 'login_recovery_code', req.ip);
    return startSession(ctx, req, reply, userId);
  });

  app.post('/api/auth/logout', async (req, reply) => {
    const token = req.cookies[cookieName(cfg)];
    if (token) await db.query('DELETE FROM sessions WHERE id_hash = $1', [sha256(token)]);
    clearSessionCookie(ctx, reply);
    return { ok: true };
  });

  app.get('/api/session', async (req) => {
    const user = requireUser(req);
    return sessionPayload(ctx, user.id, user.csrf);
  });

  // ---- device / session management ----

  app.get('/api/sessions', async (req) => {
    const user = requireUser(req);
    const { rows } = await db.query(
      'SELECT id_hash, created_at, last_seen_at, user_agent FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC',
      [user.id],
    );
    return rows.map((r) => ({
      id: Buffer.from(r.id_hash).toString('hex'),
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
      device: r.user_agent,
      current: Buffer.from(r.id_hash).equals(user.sessionHash),
    }));
  });

  app.delete('/api/sessions/:id', async (req) => {
    const user = requireUser(req);
    const { id } = z.object({ id: z.string().regex(/^[0-9a-f]{64}$/) }).parse(req.params);
    await db.query('DELETE FROM sessions WHERE id_hash = $1 AND user_id = $2', [Buffer.from(id, 'hex'), user.id]);
    await logSecurityEvent(ctx, user.id, 'session_revoked', req.ip);
    return { ok: true };
  });

  app.post('/api/sessions/revoke-others', async (req) => {
    const user = requireUser(req);
    const r = await db.query('DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2', [user.id, user.sessionHash]);
    await logSecurityEvent(ctx, user.id, 'sessions_revoked', req.ip);
    return { revoked: r.rowCount };
  });

  // ---- password change (re-wraps the Mailbox Key; mail stays readable) ----

  app.post('/api/auth/change-password', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req, reply) => {
    const user = requireUser(req);
    const body = z.object({ currentAuthKey: secret32, ...credentialSet }).parse(req.body);
    if (!(await verifyAuthKey(ctx, user.id, body.currentAuthKey))) {
      await registerFailure(ctx, user.id);
      throw new HttpError(401, 'invalid_credentials');
    }
    const authHash = await hashSecret(cfg, b64ToBuf(body.authKey));
    await tx(db, async (c) => {
      await c.query(
        'UPDATE users SET kdf_salt=$2, kdf_params=$3, auth_hash=$4, mk_wrapped_password=$5, failed_logins=0 WHERE id=$1',
        [user.id, b64ToBuf(body.salt), body.kdfParams, authHash, b64ToBuf(body.mkWrappedPassword)],
      );
      // Rotate: revoke every session including this one; a fresh one is issued below.
      await c.query('DELETE FROM sessions WHERE user_id = $1', [user.id]);
    });
    await logSecurityEvent(ctx, user.id, 'password_changed', req.ip);
    return startSession(ctx, req, reply, user.id);
  });

  // ---- recovery with recovery key: mail remains readable ----

  app.post('/api/recovery/start', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req) => {
    const body = z.object({ username: z.string().max(320), recoveryAuth: secret32 }).parse(req.body);
    const { rows } = await db.query(
      'SELECT id, recovery_auth_hash, mk_wrapped_recovery, login_locked_until, status FROM users WHERE username = $1',
      [usernameOf(body.username)],
    );
    const u = rows[0];
    if (!u || !u.recovery_auth_hash) {
      await dummyVerify(cfg);
      throw new HttpError(401, 'invalid_recovery');
    }
    if (u.login_locked_until && new Date(u.login_locked_until) > new Date()) throw new HttpError(429, 'too_many_attempts');
    if (!(await verifySecret(cfg, u.recovery_auth_hash, b64ToBuf(body.recoveryAuth)))) {
      await registerFailure(ctx, u.id);
      await logSecurityEvent(ctx, u.id, 'recovery_failed', req.ip);
      throw new HttpError(401, 'invalid_recovery');
    }
    if (u.status !== 'active') throw new HttpError(403, 'account_suspended');
    const challenge = randomToken(32);
    await db.query(
      `INSERT INTO login_challenges(id_hash, user_id, purpose, expires_at) VALUES ($1,$2,'recovery', now() + interval '15 minutes')`,
      [sha256(challenge), u.id],
    );
    return { challenge, mkWrappedRecovery: Buffer.from(u.mk_wrapped_recovery).toString('base64') };
  });

  app.post('/api/recovery/complete', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req, reply) => {
    const body = z.object({ challenge: z.string().max(64), ...credentialSet, ...recoverySet }).parse(req.body);
    const hash = sha256(body.challenge);
    const { rows } = await db.query(
      `DELETE FROM login_challenges WHERE id_hash = $1 AND purpose = 'recovery' AND expires_at > now() RETURNING user_id`,
      [hash],
    );
    if (!rows.length) throw new HttpError(401, 'challenge_expired');
    const userId = rows[0].user_id as string;
    const authHash = await hashSecret(cfg, b64ToBuf(body.authKey));
    const recHash = await hashSecret(cfg, b64ToBuf(body.recoveryAuth));
    await tx(db, async (c) => {
      await c.query(
        `UPDATE users SET kdf_salt=$2, kdf_params=$3, auth_hash=$4, mk_wrapped_password=$5,
                mk_wrapped_recovery=$6, recovery_auth_hash=$7, failed_logins=0, login_locked_until=NULL WHERE id=$1`,
        [userId, b64ToBuf(body.salt), body.kdfParams, authHash, b64ToBuf(body.mkWrappedPassword), b64ToBuf(body.mkWrappedRecovery), recHash],
      );
      await c.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
    });
    await logSecurityEvent(ctx, userId, 'recovered_with_recovery_key', req.ip);
    return startSession(ctx, req, reply, userId);
  });

  // ---- account recovery by email: regains access, NOT old mail ----

  app.post('/api/recovery/email-request', { config: { rateLimit: rl(cfg, 3, '15 minutes') } }, async (req) => {
    const { username } = z.object({ username: z.string().max(320) }).parse(req.body);
    const { rows } = await db.query("SELECT id, recovery_email FROM users WHERE username = $1 AND status = 'active'", [usernameOf(username)]);
    if (rows[0]?.recovery_email) {
      const recent = await db.query(
        "SELECT count(*)::int AS n FROM password_resets WHERE user_id = $1 AND expires_at > now() - interval '30 minutes'",
        [rows[0].id],
      );
      if (recent.rows[0].n < 3) {
        const token = randomToken(32);
        await db.query(
          `INSERT INTO password_resets(token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '30 minutes')`,
          [sha256(token), rows[0].id],
        );
        await enqueueSystemEmail(ctx, {
          to: rows[0].recovery_email,
          subject: 'VoidMail account reset request',
          text:
            `Someone asked to reset the VoidMail account ${usernameOf(username)}@${domain}.\n\n` +
            `If this was you, open this link within 30 minutes:\n${cfg.PUBLIC_ORIGIN}/#/reset/${token}\n\n` +
            `Important: resetting without your recovery key creates new encryption keys. ` +
            `Existing mail will remain permanently unreadable.\n\nIf this was not you, ignore this message.`,
        });
        await logSecurityEvent(ctx, rows[0].id, 'reset_email_requested', req.ip);
      }
    }
    // Always the same answer to avoid account enumeration.
    return { ok: true };
  });

  app.post('/api/recovery/email-complete', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req, reply) => {
    const body = z
      .object({
        token: z.string().max(64),
        acknowledgeDataLoss: z.literal(true),
        totpCode: z.string().max(24).optional(),
        ...credentialSet,
        ...recoverySet,
        ...keySet,
      })
      .parse(req.body);
    const hash = sha256(body.token);
    const { rows } = await db.query(
      `SELECT r.user_id, u.username, u.totp_enabled FROM password_resets r JOIN users u ON u.id = r.user_id
        WHERE r.token_hash = $1 AND r.expires_at > now() AND r.used_at IS NULL`,
      [hash],
    );
    if (!rows.length) throw new HttpError(401, 'invalid_token');
    const { user_id: userId, username, totp_enabled } = rows[0];
    // Email alone must not bypass 2FA.
    if (totp_enabled) {
      const code = body.totpCode?.trim() ?? '';
      const ok = /^\d{6}$/.test(code) ? await checkTotp(ctx, userId, code) : code ? await useRecoveryCode(ctx, userId, code) : false;
      if (!ok) throw new HttpError(401, 'totp_required');
    }
    await checkPublicKey(body.publicKey, body.fingerprint, `${username}@${domain}`);
    const authHash = await hashSecret(cfg, b64ToBuf(body.authKey));
    const recHash = await hashSecret(cfg, b64ToBuf(body.recoveryAuth));
    await tx(db, async (c) => {
      const used = await c.query('UPDATE password_resets SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL', [hash]);
      if (used.rowCount !== 1) throw new HttpError(401, 'invalid_token');
      await c.query(
        `UPDATE users SET kdf_salt=$2, kdf_params=$3, auth_hash=$4, mk_wrapped_password=$5, mk_wrapped_recovery=$6,
                recovery_auth_hash=$7, vault_enc=NULL, vault_version=vault_version+1, failed_logins=0, login_locked_until=NULL
          WHERE id=$1`,
        [userId, b64ToBuf(body.salt), body.kdfParams, authHash, b64ToBuf(body.mkWrappedPassword), b64ToBuf(body.mkWrappedRecovery), recHash],
      );
      // Old keys can no longer be unlocked (their Mailbox Key is gone). Keep them marked 'locked' so the UI can
      // explain why older mail is unreadable.
      await c.query(`UPDATE user_keys SET status='locked', retired_at=now() WHERE user_id=$1 AND status <> 'locked'`, [userId]);
      await c.query(
        `INSERT INTO user_keys(user_id, fingerprint, public_key, private_key_enc, revocation_cert_enc, status) VALUES ($1,$2,$3,$4,$5,'active')`,
        [userId, body.fingerprint, body.publicKey, body.privateKeyEnc, body.revocationCertEnc ? b64ToBuf(body.revocationCertEnc) : null],
      );
      await c.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
    });
    await logSecurityEvent(ctx, userId, 'reset_via_email_keys_replaced', req.ip);
    return startSession(ctx, req, reply, userId);
  });

  // ---- recovery key regeneration ----

  app.post('/api/security/recovery-key', { config: { rateLimit: rl(cfg, 5, '15 minutes') } }, async (req) => {
    const user = requireUser(req);
    const body = z.object({ authKey: secret32, ...recoverySet }).parse(req.body);
    if (!(await verifyAuthKey(ctx, user.id, body.authKey))) throw new HttpError(401, 'invalid_credentials');
    await db.query('UPDATE users SET mk_wrapped_recovery=$2, recovery_auth_hash=$3 WHERE id=$1', [
      user.id,
      b64ToBuf(body.mkWrappedRecovery),
      await hashSecret(cfg, b64ToBuf(body.recoveryAuth)),
    ]);
    await logSecurityEvent(ctx, user.id, 'recovery_key_regenerated', req.ip);
    return { ok: true };
  });

  // ---- TOTP ----

  app.post('/api/security/totp/setup', async (req) => {
    const user = requireUser(req);
    const cur = await db.query('SELECT totp_enabled FROM users WHERE id=$1', [user.id]);
    if (cur.rows[0].totp_enabled) throw new HttpError(409, 'totp_already_enabled');
    const secret = generateSecret({ length: 20 });
    await db.query('UPDATE users SET totp_secret_enc=$2, totp_last_step=NULL WHERE id=$1', [
      user.id,
      await sealServer(cfg.keys.totp, Buffer.from(secret), 'totp:' + user.id),
    ]);
    const uri = generateURI({ issuer: 'VoidMail', label: `${user.username}@${domain}`, secret });
    return { secret, uri };
  });

  app.post('/api/security/totp/enable', async (req) => {
    const user = requireUser(req);
    const { code } = z.object({ code: z.string().regex(/^\d{6}$/) }).parse(req.body);
    if (!(await checkTotp(ctx, user.id, code))) throw new HttpError(400, 'invalid_code');
    const codes = await tx(db, async (c) => {
      await c.query('UPDATE users SET totp_enabled = true WHERE id = $1', [user.id]);
      const out = await makeRecoveryCodes(ctx, user.id, c);
      await c.query('DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2', [user.id, user.sessionHash]);
      return out;
    });
    await logSecurityEvent(ctx, user.id, 'totp_enabled', req.ip);
    return { recoveryCodes: codes };
  });

  app.post('/api/security/totp/disable', async (req) => {
    const user = requireUser(req);
    const body = z.object({ authKey: secret32, code: z.string().max(24) }).parse(req.body);
    if (!(await verifyAuthKey(ctx, user.id, body.authKey))) throw new HttpError(401, 'invalid_credentials');
    const code = body.code.trim();
    const ok = /^\d{6}$/.test(code) ? await checkTotp(ctx, user.id, code) : await useRecoveryCode(ctx, user.id, code);
    if (!ok) throw new HttpError(400, 'invalid_code');
    await db.query('UPDATE users SET totp_enabled=false, totp_secret_enc=NULL, totp_last_step=NULL WHERE id=$1', [user.id]);
    await db.query('DELETE FROM recovery_codes WHERE user_id=$1', [user.id]);
    await logSecurityEvent(ctx, user.id, 'totp_disabled', req.ip);
    return { ok: true };
  });

  app.post('/api/security/recovery-codes', async (req) => {
    const user = requireUser(req);
    const { code } = z.object({ code: z.string().regex(/^\d{6}$/) }).parse(req.body);
    if (!(await checkTotp(ctx, user.id, code))) throw new HttpError(400, 'invalid_code');
    const codes = await makeRecoveryCodes(ctx, user.id);
    await logSecurityEvent(ctx, user.id, 'recovery_codes_regenerated', req.ip);
    return { recoveryCodes: codes };
  });

  app.get('/api/security/events', async (req) => {
    const user = requireUser(req);
    const { rows } = await db.query(
      'SELECT type, ip_prefix, created_at FROM security_events WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',
      [user.id],
    );
    return rows.map((r) => ({ type: r.type, ipPrefix: r.ip_prefix, at: r.created_at }));
  });

  // ---- keys ----

  app.post('/api/keys/rotate', async (req) => {
    const user = requireUser(req);
    const body = z.object(keySet).parse(req.body);
    await checkPublicKey(body.publicKey, body.fingerprint, `${user.username}@${domain}`);
    await tx(db, async (c) => {
      await c.query(`UPDATE user_keys SET status='retired', retired_at=now() WHERE user_id=$1 AND status='active'`, [user.id]);
      await c.query(
        `INSERT INTO user_keys(user_id, fingerprint, public_key, private_key_enc, revocation_cert_enc, status) VALUES ($1,$2,$3,$4,$5,'active')`,
        [user.id, body.fingerprint, body.publicKey, body.privateKeyEnc, body.revocationCertEnc ? b64ToBuf(body.revocationCertEnc) : null],
      );
    });
    await logSecurityEvent(ctx, user.id, 'key_rotated', req.ip);
    return { ok: true };
  });

  app.get('/api/keys/lookup', { config: { rateLimit: rl(cfg, 240, '1 minute') } }, async (req) => {
    requireUser(req);
    const { address } = z.object({ address: z.string().max(320) }).parse(req.query);
    const norm = normalizeAddress(address);
    if (!norm) throw new HttpError(400, 'invalid_address');
    const [local, dom] = norm.split('@');
    if (dom !== domain) return { address: norm, internal: false };
    const { rows } = await db.query(
      `SELECT k.fingerprint, k.public_key, k.status FROM user_keys k JOIN users u ON u.id = k.user_id
        WHERE u.username = $1 AND u.status = 'active' AND k.status IN ('active','retired')
        ORDER BY (k.status = 'active') DESC, k.created_at DESC`,
      [local],
    );
    const active = rows.find((r) => r.status === 'active');
    if (!active) return { address: norm, internal: true, exists: false };
    return {
      address: norm,
      internal: true,
      exists: true,
      fingerprint: active.fingerprint,
      publicKey: active.public_key,
      // Retired keys are returned only so old signatures can still be verified. Never encrypt to them.
      retired: rows.filter((r) => r.status === 'retired').map((r) => ({ fingerprint: r.fingerprint, publicKey: r.public_key })),
    };
  });

  // ---- vault (contact key pins; encrypted + signed by the client) ----

  app.get('/api/vault', async (req) => {
    const user = requireUser(req);
    const { rows } = await db.query('SELECT vault_enc, vault_version FROM users WHERE id=$1', [user.id]);
    return { version: rows[0].vault_version, data: rows[0].vault_enc ? Buffer.from(rows[0].vault_enc).toString('base64') : null };
  });

  app.put('/api/vault', async (req) => {
    const user = requireUser(req);
    const body = z.object({ version: z.number().int().min(0), data: b64(2_000_000) }).parse(req.body);
    const r = await db.query(
      'UPDATE users SET vault_enc=$2, vault_version=vault_version+1 WHERE id=$1 AND vault_version=$3 RETURNING vault_version',
      [user.id, b64ToBuf(body.data), body.version],
    );
    if (!r.rowCount) throw new HttpError(409, 'vault_conflict');
    return { version: r.rows[0].vault_version };
  });
}
