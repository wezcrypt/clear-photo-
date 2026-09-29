import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { buildApp, type Ctx } from '../../src/server/app.js';
import { ApiError, KeyChangedError, type VoidClient } from '../../src/shared/client.js';
import { openpgp, utf8Decoder } from '../../src/shared/crypto.js';
import { makeCtx, newClient, registered } from '../helpers.js';
import { openQueuePayload } from '../../src/server/outbound.js';
import { runRetention } from '../../src/server/retention.js';

let ctx: Ctx;
let app: FastifyInstance;
let alice: VoidClient;
let bob: VoidClient;
let carol: VoidClient;

const MARK = 'PLAINTEXT-MARKER-Zq81';

beforeAll(async () => {
  ctx = await makeCtx();
  app = await buildApp(ctx);
  alice = (await registered(app, 'alice')).client;
  bob = (await registered(app, 'bob')).client;
  carol = (await registered(app, 'carol')).client;
});
afterAll(async () => {
  await app.close();
  await ctx.db.end();
});

const base = { cc: [] as string[], bcc: [] as string[], attachments: [] as any[], requireTls: false };

/** Every byte Postgres stores, as text: all columns of all tables. */
async function dumpDatabase(): Promise<string> {
  const tables = (await ctx.db.query(`SELECT tablename FROM pg_tables WHERE schemaname='public'`)).rows.map((r) => r.tablename);
  let out = '';
  for (const t of tables) {
    const rows = (await ctx.db.query(`SELECT * FROM "${t}"`)).rows;
    for (const r of rows) {
      for (const v of Object.values(r)) {
        if (Buffer.isBuffer(v)) out += v.toString('latin1') + '\n' + v.toString('utf8') + '\n';
        else out += JSON.stringify(v) + '\n';
      }
    }
  }
  return out;
}

function dumpBlobs(dir = ctx.cfg.BLOB_DIR): string {
  let out = '';
  for (const e of readdirSync(dir)) {
    const p = path.join(dir, e);
    out += statSync(p).isDirectory() ? dumpBlobs(p) : readFileSync(p).toString('latin1');
  }
  return out;
}

async function pkeskCount(b64: string): Promise<number> {
  const msg = await openpgp.readMessage({ binaryMessage: Buffer.from(b64, 'base64') });
  return msg.packets.filter((p: any) => p.constructor.tag === 1).length;
}

describe('internal end-to-end encryption', () => {
  it('delivers, decrypts and verifies the signature; no plaintext is persisted', async () => {
    const att = await alice.uploadAttachment('تقرير-سري.txt', 'text/plain', new TextEncoder().encode(`attachment ${MARK} محتوى`));
    const sent = await alice.send({
      ...base,
      to: ['bob@voidmail.test'],
      subject: `Subject ${MARK} مرحبا 👋`,
      text: `Body ${MARK}\nسطر عربي`,
      attachments: [att],
    });
    expect(sent.security).toBe('e2ee');
    const items = (await bob.list({ folder: 'inbox' })).items;
    expect(items[0].header?.subject).toBe(`Subject ${MARK} مرحبا 👋`);
    expect(items[0].security).toBe('e2ee');
    const opened = await bob.open(items[0].id);
    expect(opened.signature).toBe('valid');
    expect(opened.integrity).toBe('ok');
    expect(opened.body?.text).toContain('سطر عربي');
    expect(opened.body?.attachments[0].name).toBe('تقرير-سري.txt');
    const data = await bob.downloadAttachment(opened.body!.attachments[0]);
    expect(utf8Decoder.decode(data)).toBe(`attachment ${MARK} محتوى`);

    const db = await dumpDatabase();
    expect(db).not.toContain(MARK);
    expect(db).not.toContain('سطر عربي');
    expect(db).not.toContain('تقرير');
    expect(dumpBlobs()).not.toContain(MARK);
  });

  it('marks sender copy and shows it in Sent', async () => {
    const sent = (await alice.list({ folder: 'sent' })).items;
    expect(sent[0].header?.to).toEqual(['bob@voidmail.test']);
    expect(sent[0].unread).toBe(false);
  });

  it('keeps BCC recipients private', async () => {
    await alice.send({ ...base, to: ['bob@voidmail.test'], bcc: ['carol@voidmail.test'], subject: 'bcc test', text: 'hi' });
    const bobMsg = (await bob.list({ folder: 'inbox' })).items.find((i) => i.header?.subject === 'bcc test')!;
    const carolMsg = (await carol.list({ folder: 'inbox' })).items.find((i) => i.header?.subject === 'bcc test')!;
    const aliceMsg = (await alice.list({ folder: 'sent' })).items.find((i) => i.header?.subject === 'bcc test')!;
    expect(bobMsg.header?.bcc).toBeUndefined();
    expect(carolMsg.header?.bcc).toBeUndefined();
    expect(aliceMsg.header?.bcc).toEqual(['carol@voidmail.test']);
    // Each copy is encrypted to exactly one key: Bob's ciphertext does not reveal Carol's key id.
    const raw = await bob.call('GET', `/api/messages/${bobMsg.id}`);
    expect(await pkeskCount(raw.headerEnc)).toBe(1);
    expect(await pkeskCount(raw.bodyEnc)).toBe(1);
  });

  it('rejects tampered ciphertext instead of showing altered content', async () => {
    await alice.send({ ...base, to: ['bob@voidmail.test'], subject: 'tamper me', text: 'original' });
    const msg = (await bob.list({ folder: 'inbox' })).items.find((i) => i.header?.subject === 'tamper me')!;
    const row = await ctx.db.query('SELECT body_enc FROM messages WHERE id=$1', [msg.id]);
    const body = Buffer.from(row.rows[0].body_enc);
    body[body.length - 30] ^= 0x01;
    await ctx.db.query('UPDATE messages SET body_enc=$2 WHERE id=$1', [msg.id, body]);
    const opened = await bob.open(msg.id);
    expect(opened.body).toBeNull();
  });

  it('detects header/body swapping by the server', async () => {
    await alice.send({ ...base, to: ['bob@voidmail.test'], subject: 'swap A', text: 'A' });
    await alice.send({ ...base, to: ['bob@voidmail.test'], subject: 'swap B', text: 'B' });
    const items = (await bob.list({ folder: 'inbox' })).items;
    const a = items.find((i) => i.header?.subject === 'swap A')!;
    const b = items.find((i) => i.header?.subject === 'swap B')!;
    await ctx.db.query('UPDATE messages SET body_enc = (SELECT body_enc FROM messages WHERE id=$2) WHERE id=$1', [a.id, b.id]);
    expect((await bob.open(a.id)).integrity).toBe('mismatch');
  });

  it('a different user key cannot decrypt the message', async () => {
    const msg = (await bob.list({ folder: 'inbox' })).items[0];
    const row = await ctx.db.query('SELECT header_enc FROM messages WHERE id=$1', [msg.id]);
    // Carol's keys cannot open Bob's ciphertext.
    const carolKeys = (carol as any).privateKeys as Map<string, any>;
    await expect(
      openpgp.decrypt({ message: await openpgp.readMessage({ binaryMessage: row.rows[0].header_enc }), decryptionKeys: [...carolKeys.values()] }),
    ).rejects.toThrow();
  });

  it('refuses to send when a pinned key changes, until the user accepts', async () => {
    const dave = (await registered(app, 'dave')).client;
    await alice.send({ ...base, to: ['dave@voidmail.test'], subject: 'before rotation', text: 'x' });
    expect(alice.pins()['dave@voidmail.test']).toBeTruthy();
    const newFp = await dave.rotateKey();
    (alice as any).lookupCache.clear();
    const err = await alice.send({ ...base, to: ['dave@voidmail.test'], subject: 'after rotation', text: 'y' }).catch((e) => e);
    expect(err).toBeInstanceOf(KeyChangedError);
    expect(err.changes[0].newFingerprint).toBe(newFp);
    await alice.acceptKeyChange('dave@voidmail.test', newFp);
    await alice.send({ ...base, to: ['dave@voidmail.test'], subject: 'after rotation', text: 'y' });
    const subjects = (await dave.list({ folder: 'inbox' })).items.map((i) => i.header?.subject);
    // Old mail (encrypted to the retired key) and new mail are both readable.
    expect(subjects).toContain('before rotation');
    expect(subjects).toContain('after rotation');
    const pin = alice.pins()['dave@voidmail.test'];
    expect(pin.verified).toBe(false);
    expect(pin.history?.length).toBe(1);
  });

  it('server refuses copies encrypted to a stale recipient key', async () => {
    const erin = (await registered(app, 'erin')).client;
    const oldFp = erin.activeKeyInfo().fingerprint;
    await erin.rotateKey();
    const own = alice.activeKeyInfo();
    const res = await alice
      .call('POST', '/api/send', {
        recipients: { to: ['erin@voidmail.test'] },
        sentCopy: { headerEnc: 'AAAA', bodyEnc: 'AAAA', keyFingerprint: own.fingerprint },
        internal: [{ address: 'erin@voidmail.test', headerEnc: 'AAAA', bodyEnc: 'AAAA', keyFingerprint: oldFp }],
      })
      .catch((e) => e);
    expect(res).toBeInstanceOf(ApiError);
    expect(res.code).toBe('recipient_key_changed');
  });

  it('verified status is stored in the encrypted, signed vault', async () => {
    await alice.setVerified('bob@voidmail.test', true);
    const { client: again } = await newClient(app);
    await again.login('alice', 'correct horse battery staple');
    expect(again.pins()['bob@voidmail.test'].verified).toBe(true);
    expect(await dumpDatabase()).not.toContain('bob@voidmail.test"'.slice(0, 0) + '"verified":true');
  });

  it('a forged vault is not trusted', async () => {
    // The server replaces the vault with one encrypted to Alice's public key but not signed by her.
    const pub = await openpgp.readKey({ armoredKey: alice.activeKeyInfo().publicKey });
    const forged = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: JSON.stringify({ v: 1, pins: { 'bob@voidmail.test': { fingerprint: 'ff'.repeat(20), verified: true } } }) }),
      encryptionKeys: pub,
      format: 'binary',
    });
    await ctx.db.query("UPDATE users SET vault_enc=$1 WHERE username='alice'", [Buffer.from(forged as Uint8Array)]);
    const { client: again } = await newClient(app);
    await again.login('alice', 'correct horse battery staple');
    expect(again.vaultProblem).toBe(true);
    expect(again.pins()['bob@voidmail.test']).toBeUndefined();
  });
});

describe('authorization and account isolation', () => {
  it('prevents access to other users messages, attachments, labels and delivery status', async () => {
    const att = await alice.uploadAttachment('a.bin', 'application/octet-stream', new Uint8Array([1, 2, 3]));
    await alice.send({ ...base, to: ['alice@voidmail.test'], subject: 'private', text: 'x', attachments: [att] });
    const mine = (await alice.list({ folder: 'inbox' })).items.find((i) => i.header?.subject === 'private')!;
    await expect(carol.call('GET', `/api/messages/${mine.id}`)).rejects.toMatchObject({ status: 404 });
    await carol.call('PATCH', `/api/messages/${mine.id}`, { starred: true });
    await carol.update([mine.id], { folder: 'trash' });
    await carol.update([mine.id], { delete: true });
    const still = await alice.open(mine.id);
    expect(still.starred).toBe(false);
    expect(still.folder).toBe('inbox');
    await expect(carol.downloadAttachment({ ...att })).rejects.toMatchObject({ status: 404 });
    const label = await alice.call('POST', '/api/labels', { name: 'Private' });
    await expect(carol.setLabels(mine.id, [label.id])).rejects.toMatchObject({ status: 404 });
    const carolMsg = (await carol.list({ folder: 'inbox' })).items[0];
    await expect(carol.setLabels(carolMsg.id, [label.id])).rejects.toMatchObject({ code: 'label_not_found' });
    expect(await carol.delivery(mine.id)).toEqual([]);
    await expect(carol.call('PUT', `/api/drafts/${mine.id}`, { headerEnc: 'AA==', bodyEnc: 'AA==', keyFingerprint: 'a'.repeat(40) })).rejects.toMatchObject({ status: 404 });
    // cannot attach someone else's blob
    await expect(
      carol.send({ ...base, to: ['carol@voidmail.test'], subject: 's', text: 't', attachments: [att] }),
    ).rejects.toMatchObject({ code: 'attachment_not_found' });
  });

  it('rejects unauthenticated access', async () => {
    const { client } = await newClient(app);
    await expect(client.call('GET', '/api/messages?folder=inbox')).rejects.toMatchObject({ status: 401 });
  });

  it('server enforces username rules even if a client skips them', async () => {
    const { client } = await newClient(app);
    await expect(client.call('POST', '/api/auth/register', { username: '../x' })).rejects.toMatchObject({ status: 400 });
  });

  it('rejects plaintext attachment uploads', async () => {
    const { transport, client } = await registered(app, 'uploader');
    const res = await transport('POST', '/api/attachments', {
      bytes: new TextEncoder().encode('plain text'),
      headers: { 'Content-Type': 'application/octet-stream', 'X-Requested-With': 'voidmail', 'X-CSRF-Token': client.session!.csrf },
    });
    expect(res.status).toBe(400);
    expect(res.data.error).toBe('not_openpgp_ciphertext');
  });
});

describe('external sending', () => {
  it('labels external mail honestly, strips Bcc from headers, and encrypts the queue payload', async () => {
    const att = await alice.uploadAttachment('résumé.pdf', 'application/pdf', new TextEncoder().encode('%PDF fake'));
    const plan = await alice.plan({ to: ['ext@example.org'], cc: ['bob@voidmail.test'], bcc: ['hidden@example.net'], requireTls: false });
    expect(plan.mode).toBe('standard');
    expect(plan.label).toBe('standard_tls_optional');
    const res = await alice.send({
      ...base,
      to: ['ext@example.org'],
      cc: ['bob@voidmail.test'],
      bcc: ['hidden@example.net'],
      subject: `External ${MARK} عربي`,
      text: `external body ${MARK}`,
      attachments: [att],
    });
    expect(res.security).toBe('standard_tls_optional');
    // Internal CC recipient gets the same honest label.
    const bobCopy = (await bob.list({ folder: 'inbox' })).items.find((i) => i.header?.subject?.startsWith('External'))!;
    expect(bobCopy.security).toBe('standard_tls_optional');
    const q = await ctx.db.query('SELECT * FROM outbound_queue WHERE message_id=$1', [res.id]);
    expect(q.rows[0].require_tls).toBe(false);
    expect(Buffer.from(q.rows[0].payload_enc).toString('latin1')).not.toContain(MARK);
    const rcpts = (await ctx.db.query('SELECT address FROM outbound_recipients WHERE queue_id=$1 ORDER BY address', [q.rows[0].id])).rows.map((r) => r.address);
    expect(rcpts).toEqual(['ext@example.org', 'hidden@example.net']); // internal CC is not sent via SMTP
    const mime = (await openQueuePayload(ctx.cfg, q.rows[0].id, q.rows[0].payload_enc)).toString('utf8');
    expect(mime).not.toMatch(/^bcc:/im);
    expect(mime).not.toContain('hidden@example.net');
    expect(mime).toMatch(/^To: ext@example.org/m);
    expect(mime).toMatch(/^Cc: bob@voidmail.test/m);
    expect(mime).toContain('filename');
    expect(q.rows[0].envelope_from).toMatch(/^bounces\+[0-9a-f]{32}@voidmail\.test$/);
  });

  it('require-TLS mode is recorded and uses the .tls bounce address', async () => {
    const res = await alice.send({ ...base, requireTls: true, to: ['secure@example.org'], subject: 'tls', text: 't' });
    expect(res.security).toBe('standard_tls_required');
    const q = await ctx.db.query('SELECT require_tls, envelope_from FROM outbound_queue WHERE message_id=$1', [res.id]);
    expect(q.rows[0].require_tls).toBe(true);
    expect(q.rows[0].envelope_from).toMatch(/\.tls@voidmail\.test$/);
  });

  it('server refuses plaintext for internal-only messages and missing external payloads', async () => {
    const own = alice.activeKeyInfo().fingerprint;
    await expect(
      alice.call('POST', '/api/send', {
        recipients: { to: ['ext@example.org'] },
        sentCopy: { headerEnc: 'AA==', bodyEnc: 'AA==', keyFingerprint: own },
      }),
    ).rejects.toMatchObject({ code: 'external_payload_required' });
    const bobKey = await alice.recipientKey('bob@voidmail.test');
    await expect(
      alice.call('POST', '/api/send', {
        recipients: { to: ['bob@voidmail.test'] },
        sentCopy: { headerEnc: 'AA==', bodyEnc: 'AA==', keyFingerprint: own },
        internal: [{ address: 'bob@voidmail.test', headerEnc: 'AA==', bodyEnc: 'AA==', keyFingerprint: bobKey.fingerprint }],
        external: { subject: 'leak', text: 'leak' },
      }),
    ).rejects.toMatchObject({ code: 'plaintext_not_allowed_for_e2ee' });
  });

  it('rejects header injection attempts', async () => {
    await expect(alice.send({ ...base, to: ['x@example.org\r\nBcc: victim@example.com'], subject: 's', text: 't' })).rejects.toMatchObject({ code: 'invalid_address' });
    await expect(alice.send({ ...base, to: ['x@example.org'], subject: 'hi\r\nBcc: victim@example.com', text: 't' })).rejects.toMatchObject({ code: 'invalid_subject' });
  });

  it('enforces the per-message recipient cap and daily external limit', async () => {
    const many = Array.from({ length: 51 }, (_, i) => `r${i}@example.org`);
    await expect(alice.send({ ...base, to: many, subject: 's', text: 't' })).rejects.toMatchObject({ code: 'too_many_recipients' });
    const spammer = (await registered(app, 'spammer')).client;
    await ctx.db.query(`INSERT INTO send_log(user_id, external, internal) SELECT id, 199, 0 FROM users WHERE username='spammer'`);
    await expect(spammer.send({ ...base, to: ['a@example.org', 'b@example.org'], subject: 's', text: 't' })).rejects.toMatchObject({ code: 'daily_external_limit' });
  });

  it('enforces the per-minute send rate', async () => {
    const burst = (await registered(app, 'burst')).client;
    await ctx.db.query(`INSERT INTO send_log(user_id, external, internal) SELECT id, 0, 1 FROM users, generate_series(1, 1000) WHERE username='burst'`);
    await expect(burst.send({ ...base, to: ['burst@voidmail.test'], subject: 's', text: 't' })).rejects.toMatchObject({ code: 'send_rate_limited' });
  });
});

describe('mailbox features', () => {
  it('drafts are encrypted, autosave-updatable, and removed on send', async () => {
    const draft = { ...base, to: ['bob@voidmail.test'], subject: `Draft ${MARK}`, text: 'v1' };
    const id = await alice.saveDraft(draft);
    await alice.saveDraft({ ...draft, text: 'v2', draftId: id });
    const drafts = (await alice.list({ folder: 'drafts' })).items;
    expect(drafts.length).toBe(1);
    const opened = await alice.open(id);
    expect(opened.body?.text).toBe('v2');
    expect(opened.signature).toBe('valid');
    expect(await dumpDatabase()).not.toContain(MARK);
    await alice.send({ ...draft, text: 'v2', draftId: id });
    expect((await alice.list({ folder: 'drafts' })).items.length).toBe(0);
  });

  it('supports flags, folders, restore, labels and pagination', async () => {
    const f = (await registered(app, 'frank')).client;
    for (let i = 0; i < 7; i++) await f.send({ ...base, to: ['frank@voidmail.test'], subject: `m${i}`, text: 'x' });
    const p1 = await f.list({ folder: 'inbox', limit: 3 });
    expect(p1.items.map((i) => i.header?.subject)).toEqual(['m6', 'm5', 'm4']);
    const p2 = await f.list({ folder: 'inbox', limit: 3, before: p1.next });
    expect(p2.items.map((i) => i.header?.subject)).toEqual(['m3', 'm2', 'm1']);
    const p3 = await f.list({ folder: 'inbox', limit: 3, before: p2.next });
    expect(p3.items.length).toBe(1);
    expect(p3.next).toBeNull();

    const target = p1.items[0].id;
    await f.update([target], { unread: false, starred: true });
    expect((await f.list({ folder: 'starred' })).items[0].id).toBe(target);
    await f.update([target], { folder: 'archive' });
    expect((await f.list({ folder: 'archive' })).items[0].id).toBe(target);
    await f.update([target], { folder: 'trash' });
    await f.update([target], { folder: 'restore' });
    expect((await f.open(target)).folder).toBe('archive');
    const label = await f.call('POST', '/api/labels', { name: 'Work' });
    await f.setLabels(target, [label.id]);
    expect((await f.list({ label: label.id })).items.map((i) => i.id)).toEqual([target]);
    // sent mail cannot be moved to inbox
    const sentId = (await f.list({ folder: 'sent' })).items[0].id;
    await f.update([sentId], { folder: 'inbox' });
    expect((await f.open(sentId)).folder).toBe('sent');
    // permanent delete only from trash
    await f.update([p1.items[1].id], { delete: true });
    expect((await f.open(p1.items[1].id)).folder).toBe('inbox');
    const counts = await f.call('GET', '/api/messages/counts');
    expect(counts.inbox.total).toBe(6);
  });

  it('enforces quotas for sender and recipient', async () => {
    const g = (await registered(app, 'grace')).client;
    await ctx.db.query("UPDATE users SET quota_bytes = 2000 WHERE username='grace'");
    await expect(g.uploadAttachment('big.bin', 'application/octet-stream', new Uint8Array(5000))).rejects.toMatchObject({ code: 'quota_exceeded' });
    await expect(alice.send({ ...base, to: ['grace@voidmail.test'], subject: 'x'.repeat(10), text: 'y'.repeat(3000) })).rejects.toMatchObject({ code: 'recipient_over_quota' });
    const q = await g.call('GET', '/api/quota');
    expect(q.quota).toBe(2000);
  });

  it('retention purges old trash and orphaned attachment blobs', async () => {
    const h = (await registered(app, 'henry')).client;
    const att = await h.uploadAttachment('t.txt', 'text/plain', new Uint8Array([9, 9, 9]));
    await h.send({ ...base, to: ['henry@voidmail.test'], subject: 'old', text: 'x', attachments: [att] });
    const ids = [...(await h.list({ folder: 'inbox' })).items, ...(await h.list({ folder: 'sent' })).items].map((i) => i.id);
    await h.update(ids, { folder: 'trash' });
    await ctx.db.query(`UPDATE messages SET folder_changed_at = now() - interval '31 days' WHERE id = ANY($1::uuid[])`, [ids]);
    const before = (await ctx.db.query('SELECT storage_key FROM blobs WHERE id=$1', [att.id])).rows[0].storage_key;
    await ctx.db.query(`UPDATE blobs SET created_at = now() - interval '2 days' WHERE id=$1`, [att.id]);
    const report = await runRetention(ctx);
    expect(report.trashPurged).toBeGreaterThanOrEqual(2);
    expect(report.orphanBlobs).toBeGreaterThanOrEqual(1);
    expect((await h.list({ folder: 'trash' })).items.length).toBe(0);
    await expect(ctx.blobs.get(before)).rejects.toThrow();
  });

  it('exports decrypted mail client-side and deletes the account', async () => {
    const i = await registered(app, 'ivan');
    const att = await i.client.uploadAttachment('x.txt', 'text/plain', new TextEncoder().encode('export me'));
    await i.client.send({ ...base, to: ['ivan@voidmail.test'], subject: 'export test', text: 'body', attachments: [att] });
    const exp = (await i.client.exportAll()) as any;
    expect(exp.messages.length).toBe(2);
    expect(exp.messages[0].header.subject).toBe('export test');
    expect(Buffer.from(exp.messages[0].attachments[0].base64, 'base64').toString()).toBe('export me');
    const key = (await ctx.db.query('SELECT storage_key FROM blobs WHERE id=$1', [att.id])).rows[0].storage_key;

    await expect(i.client.deleteAccount('wrong password here')).rejects.toMatchObject({ code: 'invalid_credentials' });
    await i.client.deleteAccount(i.password);
    const left = await ctx.db.query(`SELECT count(*)::int AS n FROM messages m JOIN users u ON u.id=m.user_id WHERE u.username='ivan'`);
    expect(left.rows[0].n).toBe(0);
    expect((await ctx.db.query("SELECT 1 FROM users WHERE username='ivan'")).rowCount).toBe(0);
    await expect(ctx.blobs.get(key)).rejects.toThrow();
    // The address cannot be re-registered by someone else.
    const { client } = await newClient(app);
    await expect(client.register({ username: 'ivan', password: 'new owner password' })).rejects.toMatchObject({ code: 'username_taken' });
  });

  it('keeps shared attachment blobs when only one party deletes their account', async () => {
    const j = await registered(app, 'judy');
    const att = await j.client.uploadAttachment('shared.txt', 'text/plain', new TextEncoder().encode('shared'));
    await j.client.send({ ...base, to: ['bob@voidmail.test'], subject: 'shared blob', text: 'x', attachments: [att] });
    await j.client.deleteAccount(j.password);
    const m = (await bob.list({ folder: 'inbox' })).items.find((x) => x.header?.subject === 'shared blob')!;
    const opened = await bob.open(m.id);
    expect(utf8Decoder.decode(await bob.downloadAttachment(opened.body!.attachments[0]))).toBe('shared');
  });
});
