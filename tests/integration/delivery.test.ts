import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { buildApp, type Ctx } from '../../src/server/app.js';
import type { VoidClient } from '../../src/shared/client.js';
import { makeCtx, registered } from '../helpers.js';
import { processInbound, InboundError } from '../../src/server/inbound.js';
import { claim, deliverRow, runOnce, type RelayTransport } from '../../src/server/worker.js';
import { lookupServer } from '../../src/server/lookup.js';

let ctx: Ctx;
let app: FastifyInstance;
let alice: VoidClient;

beforeAll(async () => {
  ctx = await makeCtx();
  app = await buildApp(ctx);
  alice = (await registered(app, 'alice')).client;
});
afterAll(async () => {
  await app.close();
  await ctx.db.end();
});

const MARK = 'INBOUND-MARKER-44k';

function crlf(s: string) {
  return Buffer.from(s.replace(/\r?\n/g, '\r\n'));
}

const multipart = crlf(`From: "Sender Ümlaut" <sender@example.org>
To: alice@voidmail.test
Subject: =?UTF-8?B?${Buffer.from(`مرحبا ${MARK}`).toString('base64')}?=
Message-ID: <abc123@example.org>
Date: Mon, 28 Sep 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: multipart/alternative; boundary="b2"

--b2
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Plain ${MARK} نص عربي
--b2
Content-Type: text/html; charset=utf-8

<p>HTML ${MARK}</p><img src="https://tracker.example/pixel.gif"><script>alert(1)</script>
--b2--
--b1
Content-Type: application/pdf; name="=?UTF-8?B?${Buffer.from('فاتورة.pdf').toString('base64')}?="
Content-Disposition: attachment; filename*=UTF-8''%D9%81%D8%A7%D8%AA%D9%88%D8%B1%D8%A9.pdf
Content-Transfer-Encoding: base64

${Buffer.from(`%PDF ${MARK}`).toString('base64')}
--b1--
`);

describe('inbound external mail', () => {
  it('parses MIME/Unicode/attachments, encrypts on arrival, and stores no plaintext', async () => {
    const res = await processInbound(ctx, multipart, ['alice@voidmail.test']);
    expect(res).toEqual(['2.0.0 Delivered']);
    const items = (await alice.list({ folder: 'inbox' })).items;
    expect(items[0].security).toBe('external_encrypted_on_arrival');
    expect(items[0].header?.subject).toBe(`مرحبا ${MARK}`);
    expect(items[0].header?.from).toEqual({ name: 'Sender Ümlaut', address: 'sender@example.org' });
    const opened = await alice.open(items[0].id);
    expect(opened.signature).toBe('n/a'); // external mail is not signed; UI says so
    expect(opened.body?.text).toContain('نص عربي');
    expect(opened.body?.html).toContain('<script>'); // raw HTML is kept; it is sanitized at render time in the browser
    expect(opened.body?.attachments[0].name).toBe('فاتورة.pdf');
    expect(new TextDecoder().decode(await alice.downloadAttachment(opened.body!.attachments[0]))).toBe(`%PDF ${MARK}`);

    const rows = (await ctx.db.query('SELECT header_enc, body_enc FROM messages WHERE id=$1', [items[0].id])).rows[0];
    expect(Buffer.from(rows.header_enc).toString('latin1')).not.toContain(MARK);
    expect(Buffer.from(rows.body_enc).toString('latin1')).not.toContain(MARK);
  });

  it('ignores duplicate LMTP deliveries of the same message', async () => {
    const res = await processInbound(ctx, multipart, ['alice@voidmail.test']);
    expect(res).toEqual(['2.0.0 Duplicate ignored']);
    const n = await ctx.db.query(`SELECT count(*)::int AS n FROM messages WHERE kind='external_in'`);
    expect(n.rows[0].n).toBe(1);
  });

  it('returns per-recipient LMTP results and rejects unknown users', async () => {
    const raw = crlf('From: x@example.org\nTo: a@voidmail.test\nSubject: hi\n\nbody\n');
    const res = await processInbound(ctx, raw, ['alice@voidmail.test', 'nobody@voidmail.test', 'alice@other.example']);
    expect(res[0]).toBe('2.0.0 Delivered');
    expect(res[1]).toBeInstanceOf(InboundError);
    expect((res[1] as InboundError).responseCode).toBe(550);
    expect((res[2] as InboundError).responseCode).toBe(550);
  });

  it('routes upstream-flagged spam to the Spam folder', async () => {
    const raw = crlf('From: spam@example.org\nTo: alice@voidmail.test\nSubject: win\nX-Spam-Flag: YES\n\nbuy\n');
    await processInbound(ctx, raw, ['alice@voidmail.test']);
    expect((await alice.list({ folder: 'spam' })).items[0].header?.subject).toBe('win');
  });

  it('rejects mail for a full mailbox with 552', async () => {
    const full = (await registered(app, 'fullbox')).client;
    void full;
    await ctx.db.query("UPDATE users SET quota_bytes = 10 WHERE username='fullbox'");
    const res = await processInbound(ctx, crlf('From: x@example.org\nTo: fullbox@voidmail.test\nSubject: s\n\nbody\n'), ['fullbox@voidmail.test']);
    expect((res[0] as InboundError).responseCode).toBe(552);
  });
});

describe('Postfix recipient lookup (tcp_table)', () => {
  it('answers 200 only for existing local users and live bounce addresses', async () => {
    const server = lookupServer(ctx);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    const ask = (key: string) =>
      new Promise<string>((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => s.write(`get ${encodeURIComponent(key)}\n`));
        s.setEncoding('utf8');
        s.once('data', (d: string) => {
          resolve(d.trim());
          s.end();
        });
      });
    expect(await ask('alice@voidmail.test')).toBe('200 OK');
    expect(await ask('nobody@voidmail.test')).toMatch(/^500/);
    expect(await ask('someone@gmail.com')).toMatch(/^500/);
    expect(await ask('@voidmail.test')).toMatch(/^500/);
    expect(await ask('bounces+' + '0'.repeat(32) + '@voidmail.test')).toMatch(/^500/);
    server.close();
  });
});

describe('outbound worker', () => {
  function fakeRelay(behaviour: (n: number) => 'ok' | 'temp' | 'perm'): RelayTransport & { sent: { to: string[]; raw: Buffer }[] } {
    let n = 0;
    const sent: { to: string[]; raw: Buffer }[] = [];
    return {
      sent,
      async send(env, raw) {
        const b = behaviour(++n);
        if (b === 'temp') throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
        if (b === 'perm') throw Object.assign(new Error('554 relay denied'), { responseCode: 554 });
        sent.push({ to: env.to, raw: Buffer.from(raw) });
        return { accepted: env.to, rejected: [] };
      },
    };
  }

  const send = (subject: string, to = ['ext@example.org']) =>
    alice.send({ to, cc: [], bcc: [], subject, text: 'hello', attachments: [], requireTls: false });

  it('relays once, deletes the payload, and never resends', async () => {
    const { id } = await send('worker ok');
    const relay = fakeRelay(() => 'ok');
    expect(await runOnce(ctx, relay)).toBe(1);
    expect(relay.sent.length).toBe(1);
    expect(relay.sent[0].raw.toString()).toContain('Subject: worker ok');
    const q = (await ctx.db.query('SELECT * FROM outbound_queue WHERE message_id=$1', [id])).rows[0];
    expect(q.status).toBe('relayed');
    expect(q.payload_enc).toBeNull();
    expect(await runOnce(ctx, relay)).toBe(0);
    expect(relay.sent.length).toBe(1);
    const status = await alice.delivery(id);
    expect(status[0].status).toBe('relayed');
  });

  it('concurrent workers never claim the same message', async () => {
    for (let i = 0; i < 6; i++) await send('concurrent ' + i);
    const [a, b, c] = await Promise.all([claim(ctx, 10), claim(ctx, 10), claim(ctx, 10)]);
    const ids = [...a, ...b, ...c].map((r) => r.id);
    expect(ids.length).toBe(6);
    expect(new Set(ids).size).toBe(6);
    const relay = fakeRelay(() => 'ok');
    for (const r of [...a, ...b, ...c]) await deliverRow(ctx, relay, r);
    expect(relay.sent.length).toBe(6);
  });

  it('retries temporary failures with backoff and gives up permanently on 5xx', async () => {
    const { id } = await send('retry me');
    const relay = fakeRelay(() => 'temp');
    await runOnce(ctx, relay);
    let q = (await ctx.db.query('SELECT * FROM outbound_queue WHERE message_id=$1', [id])).rows[0];
    expect(q.status).toBe('queued');
    expect(q.attempts).toBe(1);
    expect(new Date(q.next_attempt_at).getTime()).toBeGreaterThan(Date.now() + 20_000);
    expect(q.payload_enc).not.toBeNull();
    // not due yet -> nothing claimed
    expect(await runOnce(ctx, relay)).toBe(0);
    await ctx.db.query('UPDATE outbound_queue SET next_attempt_at = now() WHERE id=$1', [q.id]);
    const ok = fakeRelay(() => 'ok');
    await runOnce(ctx, ok);
    q = (await ctx.db.query('SELECT * FROM outbound_queue WHERE message_id=$1', [id])).rows[0];
    expect(q.status).toBe('relayed');
    expect(q.attempts).toBe(2);

    const { id: id2 } = await send('permanent fail');
    await runOnce(ctx, fakeRelay(() => 'perm'));
    const q2 = (await ctx.db.query('SELECT * FROM outbound_queue WHERE message_id=$1', [id2])).rows[0];
    expect(q2.status).toBe('failed');
    expect(q2.payload_enc).toBeNull();
    const inbox = (await alice.list({ folder: 'inbox' })).items;
    expect(inbox[0].header?.subject).toBe('Delivery failed');
    expect(inbox[0].security).toBe('system');
  });

  it('recovers a row whose worker crashed mid-send (expired lease)', async () => {
    const { id } = await send('crashed worker');
    const [row] = await claim(ctx, 1);
    expect(row).toBeTruthy();
    // Worker "dies": lease expires.
    await ctx.db.query(`UPDATE outbound_queue SET lease_until = now() - interval '1 second' WHERE id=$1`, [row.id]);
    const relay = fakeRelay(() => 'ok');
    await runOnce(ctx, relay);
    const q = (await ctx.db.query('SELECT status FROM outbound_queue WHERE message_id=$1', [id])).rows[0];
    expect(q.status).toBe('relayed');
  });

  it('processes DSN bounces: updates recipient status and notifies the sender once', async () => {
    const { id } = await send('will bounce', ['missing@example.org']);
    await runOnce(ctx, fakeRelay(() => 'ok'));
    const q = (await ctx.db.query('SELECT id, envelope_from FROM outbound_queue WHERE message_id=$1', [id])).rows[0];
    const dsn = crlf(`From: MAILER-DAEMON@mx.voidmail.test
To: ${q.envelope_from}
Subject: Undelivered Mail Returned to Sender
Auto-Submitted: auto-replied
MIME-Version: 1.0
Content-Type: multipart/report; report-type=delivery-status; boundary="r1"

--r1
Content-Type: text/plain

The mail system could not deliver your message.
--r1
Content-Type: message/delivery-status

Reporting-MTA: dns; mx.voidmail.test

Final-Recipient: rfc822; missing@example.org
Original-Recipient: rfc822;missing@example.org
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 5.1.1 User unknown
--r1--
`);
    const res = await processInbound(ctx, dsn, [q.envelope_from]);
    expect(res).toEqual(['2.0.0 Bounce processed']);
    await processInbound(ctx, Buffer.concat([dsn, Buffer.from('\r\n')]), [q.envelope_from]); // repeated DSN
    const status = await alice.delivery(id);
    expect(status[0].status).toBe('bounced');
    expect(status[0].diagnostic).toContain('5.1.1');
    const notices = (await alice.list({ folder: 'inbox' })).items.filter((i) => i.header?.subject === 'Delivery failed');
    const opened = await Promise.all(notices.map((n) => alice.open(n.id)));
    expect(opened.filter((o) => o.body?.text.includes('missing@example.org')).length).toBe(1);
    // Bounces are never delivered to a mailbox as regular mail and never trigger outbound mail.
    const out = await ctx.db.query(`SELECT count(*)::int AS n FROM outbound_queue WHERE rfc_message_id LIKE '%' AND kind='system'`);
    expect(out.rows[0].n).toBe(0);
  });
});
