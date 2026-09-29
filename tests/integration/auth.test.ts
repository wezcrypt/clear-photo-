import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { generate } from 'otplib';
import { buildApp, type Ctx } from '../../src/server/app.js';
import { ApiError, VoidClient } from '../../src/shared/client.js';
import { injectTransport, makeCtx, newClient, registered } from '../helpers.js';
import { openQueuePayload } from '../../src/server/outbound.js';
import { runRetention } from '../../src/server/retention.js';

let ctx: Ctx;
let app: FastifyInstance;

beforeAll(async () => {
  ctx = await makeCtx();
  app = await buildApp(ctx);
});
afterAll(async () => {
  await app.close();
  await ctx.db.end();
});

async function inbox(c: VoidClient) {
  return (await c.list({ folder: 'inbox' })).items;
}

describe('registration and login', () => {
  it('never sends the password to the server and login unlocks keys', async () => {
    const password = 'unique-password-marker-7731';
    const seen: string[] = [];
    const base = injectTransport(app);
    const spy: typeof base = Object.assign(async (m: string, p: string, o?: any) => {
      seen.push(JSON.stringify(o?.json ?? ''));
      return base(m, p, o);
    }, { cookies: base.cookies });
    const c = new VoidClient(spy);
    await c.register({ username: 'pwcheck', password });
    await c.logout();
    await c.login('pwcheck', password);
    expect(c.unlocked).toBe(true);
    expect(seen.join('\n')).not.toContain(password);
    const row = await ctx.db.query("SELECT auth_hash FROM users WHERE username='pwcheck'");
    expect(row.rows[0].auth_hash).toMatch(/^\$argon2id\$/);
  });

  it('rejects wrong passwords with the same error as unknown users', async () => {
    await registered(app, 'alice1');
    const { client } = await newClient(app);
    const e1 = await client.login('alice1', 'wrong password!!').catch((e) => e);
    const e2 = await client.login('nobody-here', 'wrong password!!').catch((e) => e);
    expect(e1).toBeInstanceOf(ApiError);
    expect(e1.code).toBe('invalid_credentials');
    expect(e2.code).toBe('invalid_credentials');
    expect(e1.status).toBe(e2.status);
  });

  it('pre-login returns stable decoy salts for unknown users', async () => {
    const { client } = await newClient(app);
    const a = await client.call('POST', '/api/auth/prelogin', { username: 'ghost' });
    const b = await client.call('POST', '/api/auth/prelogin', { username: 'ghost' });
    const real = await client.call('POST', '/api/auth/prelogin', { username: 'alice1' });
    expect(a.salt).toBe(b.salt);
    expect(Object.keys(a).sort()).toEqual(Object.keys(real).sort());
  });

  it('rejects duplicate and reserved usernames', async () => {
    const { client } = await newClient(app);
    await expect(client.register({ username: 'alice1', password: 'another good password' })).rejects.toMatchObject({ code: 'username_taken' });
    await expect(client.register({ username: 'postmaster', password: 'another good password' })).rejects.toMatchObject({ code: 'username_taken' });
    await expect(client.register({ username: 'Bad Name', password: 'another good password' })).rejects.toMatchObject({ code: 'invalid_username' });
  });

  it('throttles an account after repeated failures', async () => {
    await registered(app, 'throttled');
    const { client } = await newClient(app);
    for (let i = 0; i < 5; i++) await client.login('throttled', 'bad password ' + i).catch(() => undefined);
    await expect(client.login('throttled', 'correct horse battery staple')).rejects.toMatchObject({ code: 'too_many_attempts' });
  });
});

describe('CSRF and origin protection', () => {
  it('requires the CSRF token for authenticated mutations', async () => {
    const { transport } = await registered(app, 'csrfuser');
    const res = await transport('POST', '/api/labels', { json: { name: 'x' }, headers: { 'X-Requested-With': 'voidmail' } });
    expect(res.status).toBe(403);
    expect(res.data.error).toBe('csrf');
  });
  it('rejects cross-origin requests', async () => {
    const { transport, client } = await registered(app, 'originuser');
    const res = await transport('POST', '/api/labels', {
      json: { name: 'x' },
      headers: { 'X-Requested-With': 'voidmail', 'X-CSRF-Token': client.session!.csrf, Origin: 'https://evil.example' },
    });
    expect(res.status).toBe(403);
  });
  it('requires the custom header on public mutations (login CSRF)', async () => {
    const t = injectTransport(app);
    const res = await t('POST', '/api/auth/prelogin', { json: { username: 'x' } });
    expect(res.status).toBe(403);
  });
  it('sets strict security headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health' });
    expect(res.headers['content-security-policy']).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });
});

describe('sessions', () => {
  it('lists devices and revokes other sessions', async () => {
    const a = await registered(app, 'multidev');
    const { client: b } = await newClient(app);
    await b.login('multidev', a.password);
    const sessions = await a.client.call('GET', '/api/sessions');
    expect(sessions.length).toBe(2);
    expect(sessions.filter((s: any) => s.current).length).toBe(1);
    await a.client.call('POST', '/api/sessions/revoke-others');
    await expect(b.call('GET', '/api/session')).rejects.toMatchObject({ status: 401 });
    await expect(a.client.call('GET', '/api/session')).resolves.toBeTruthy();
  });

  it('revokes a specific session and logout invalidates the cookie', async () => {
    const a = await registered(app, 'revoker');
    const { client: b, transport: tb } = await newClient(app);
    await b.login('revoker', a.password);
    const other = (await a.client.call('GET', '/api/sessions')).find((s: any) => !s.current);
    await a.client.call('DELETE', `/api/sessions/${other.id}`);
    await expect(b.call('GET', '/api/session')).rejects.toMatchObject({ status: 401 });
    const cookie = [...a.transport.cookies][0];
    await a.client.logout();
    const replay = await app.inject({ method: 'GET', url: '/api/session', headers: { cookie: `${cookie[0]}=${cookie[1]}` } });
    expect(replay.statusCode).toBe(401);
    void tb;
  });

  it('stores only session token hashes', async () => {
    const a = await registered(app, 'hashcheck');
    const token = [...a.transport.cookies.values()][0];
    const rows = await ctx.db.query('SELECT id_hash FROM sessions');
    for (const r of rows.rows) expect(Buffer.from(r.id_hash).toString('base64url')).not.toBe(token);
    expect(JSON.stringify(rows.rows)).not.toContain(token);
  });
});

describe('TOTP', () => {
  it('enables 2FA, requires the code at login, blocks replay, and accepts single-use recovery codes', async () => {
    const a = await registered(app, 'totpuser');
    const { secret } = await a.client.totpSetup();
    const code = await generate({ secret });
    const codes = await a.client.totpEnable(code);
    expect(codes).toHaveLength(10);

    const { client: b } = await newClient(app);
    const step1 = await b.login('totpuser', a.password);
    expect(step1.mfaRequired).toBe(true);
    // The code already used for enabling cannot be replayed.
    await expect(b.loginTotp((step1 as any).challenge, code)).rejects.toMatchObject({ code: 'invalid_code' });
    await b.loginTotp((step1 as any).challenge, codes[0]);
    expect(b.unlocked).toBe(true);

    const { client: c } = await newClient(app);
    const s2 = await c.login('totpuser', a.password);
    await expect(c.loginTotp((s2 as any).challenge, codes[0])).rejects.toMatchObject({ code: 'invalid_code' });
    const secretRow = await ctx.db.query("SELECT totp_secret_enc FROM users WHERE username='totpuser'");
    expect(Buffer.from(secretRow.rows[0].totp_secret_enc).toString('latin1')).not.toContain(secret);
  });
});

describe('password change and recovery', () => {
  it('password change keeps mail readable and rotates sessions', async () => {
    const a = await registered(app, 'pwchange');
    await a.client.send({ to: ['pwchange@voidmail.test'], cc: [], bcc: [], subject: 'before change', text: 'still readable', attachments: [], requireTls: false });
    const { client: other } = await newClient(app);
    await other.login('pwchange', a.password);
    await a.client.changePassword(a.password, 'brand new password 42');
    await expect(other.call('GET', '/api/session')).rejects.toMatchObject({ status: 401 });
    const { client: fresh } = await newClient(app);
    await expect(fresh.login('pwchange', a.password)).rejects.toMatchObject({ code: 'invalid_credentials' });
    await fresh.login('pwchange', 'brand new password 42');
    expect((await inbox(fresh))[0].header?.subject).toBe('before change');
  });

  it('recovery key resets the password and preserves mail; the old recovery key stops working', async () => {
    const a = await registered(app, 'reckey');
    await a.client.send({ to: ['reckey@voidmail.test'], cc: [], bcc: [], subject: 'keep me', text: 'x', attachments: [], requireTls: false });
    const { client } = await newClient(app);
    const newRecovery = await client.recoverWithKey('reckey', a.recoveryKey, 'recovered password 99');
    expect(newRecovery).not.toBe(a.recoveryKey);
    expect((await inbox(client))[0].header?.subject).toBe('keep me');
    await expect(a.client.call('GET', '/api/session')).rejects.toMatchObject({ status: 401 });
    const { client: again } = await newClient(app);
    await expect(again.recoverWithKey('reckey', a.recoveryKey, 'x password 123')).rejects.toMatchObject({ code: 'invalid_recovery' });
    const { client: login } = await newClient(app);
    await login.login('reckey', 'recovered password 99');
    expect(login.unlocked).toBe(true);
  });

  it('a wrong recovery key gets a generic error', async () => {
    const { client } = await newClient(app);
    const fake = 'AAAA-'.repeat(12) + 'AAAA';
    await expect(client.recoverWithKey('reckey', fake, 'whatever password')).rejects.toMatchObject({ code: 'invalid_recovery' });
    await expect(client.recoverWithKey('no-such-user', fake, 'whatever password')).rejects.toMatchObject({ code: 'invalid_recovery' });
  });

  it('email reset restores access but old mail becomes unreadable', async () => {
    const a = await registered(app, 'emailreset', undefined, { recoveryEmail: 'me@elsewhere.example' });
    await a.client.send({ to: ['emailreset@voidmail.test'], cc: [], bcc: [], subject: 'old secret', text: 'x', attachments: [], requireTls: false });
    const { client } = await newClient(app);
    await client.requestEmailReset('emailreset');
    await client.requestEmailReset('does-not-exist'); // same response, no mail
    const q = await ctx.db.query("SELECT id, payload_enc FROM outbound_queue WHERE kind='system' ORDER BY created_at DESC");
    expect(q.rowCount).toBe(1);
    const mime = (await openQueuePayload(ctx.cfg, q.rows[0].id, q.rows[0].payload_enc)).toString();
    const token = /#\/reset\/([A-Za-z0-9_-]+)/.exec(mime.replace(/=\r\n/g, ''))![1];
    const newRecovery = await client.completeEmailReset({ token, username: 'emailreset', newPassword: 'after reset password' });
    expect(newRecovery).toBeTruthy();
    const items = await inbox(client);
    expect(items[0].header).toBeNull(); // encrypted to a key whose Mailbox Key is gone
    expect(items[0].error).toBe('undecryptable');
    await client.send({ to: ['emailreset@voidmail.test'], cc: [], bcc: [], subject: 'new mail', text: 'y', attachments: [], requireTls: false });
    expect((await inbox(client))[0].header?.subject).toBe('new mail');
    // token is single use
    const { client: c2 } = await newClient(app);
    await expect(c2.completeEmailReset({ token, username: 'emailreset', newPassword: 'again password 1' })).rejects.toMatchObject({ code: 'invalid_token' });
  });

  it('suspended accounts cannot log in', async () => {
    const a = await registered(app, 'suspendme');
    await ctx.db.query("UPDATE users SET status='suspended' WHERE username='suspendme'");
    await expect(a.client.call('GET', '/api/session')).rejects.toMatchObject({ status: 401 });
    const { client } = await newClient(app);
    await expect(client.login('suspendme', a.password)).rejects.toMatchObject({ code: 'account_suspended' });
  });

  it('retention removes expired sessions and old security events', async () => {
    await ctx.db.query("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE user_id = (SELECT id FROM users WHERE username='alice1')");
    await ctx.db.query("UPDATE security_events SET created_at = now() - interval '40 days' WHERE type='register'");
    const report = await runRetention(ctx);
    expect(report.sessions).toBeGreaterThan(0);
    expect(report.securityEvents).toBeGreaterThan(0);
  });
});
