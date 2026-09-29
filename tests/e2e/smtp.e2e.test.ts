// Full-stack tests against `docker compose up` (Postfix + bridge + worker + Mailpit sinks). No real email leaves the machine.
import { beforeAll, describe, expect, it } from 'vitest';
import nodemailer from 'nodemailer';
import { compose, mailpitRaw, mailpitSearch, MAILPIT, MAILPIT_TLS, newUser, SMTP_PORT, uniq, waitFor } from './live.js';
import type { VoidClient } from '../../src/shared/client.js';

let alice: Awaited<ReturnType<typeof newUser>>;
let bob: Awaited<ReturnType<typeof newUser>>;

const remote = () =>
  nodemailer.createTransport({ host: '127.0.0.1', port: SMTP_PORT, secure: false, tls: { rejectUnauthorized: false }, name: 'remote.example.org' });

async function findInbox(c: VoidClient, subject: string, folder = 'inbox') {
  return waitFor(async () => (await c.list({ folder })).items.find((i) => i.header?.subject === subject));
}

function queueJson(): any[] {
  const out = compose(['exec', '-T', 'postfix', 'postqueue', '-j']).trim();
  return out ? out.split('\n').map((l) => JSON.parse(l)) : [];
}

beforeAll(async () => {
  alice = await newUser('alice');
  bob = await newUser('bob');
});

describe('two local accounts', () => {
  it('exchange end-to-end encrypted mail through the live API', async () => {
    const subject = `e2ee ${uniq()} مرحبا`;
    const res = await alice.client.send({ to: [bob.address], cc: [], bcc: [], subject, text: 'hi bob', attachments: [], requireTls: false });
    expect(res.security).toBe('e2ee');
    const m = await findInbox(bob.client, subject);
    const opened = await bob.client.open(m.id);
    expect(opened.signature).toBe('valid');
    expect(opened.body?.text).toBe('hi bob');
    // Nothing was handed to Postfix for an internal message.
    expect(await mailpitSearch(MAILPIT, `subject:"${subject}"`)).toHaveLength(0);
  });
});

describe('inbound SMTP (Postfix → LMTP bridge)', () => {
  it('accepts mail for a local user, encrypts on arrival, keeps Unicode and attachments', async () => {
    const subject = `inbound ${uniq()} عربي ✓`;
    await remote().sendMail({
      from: '"Remote Sender" <sender@remote.example.org>',
      to: alice.address,
      subject,
      text: 'plain body — نص',
      html: '<p>html <b>body</b></p><img src="https://tracker.example/p.gif">',
      attachments: [{ filename: 'تقرير.txt', content: 'attached content' }],
    });
    const item = await findInbox(alice.client, subject);
    expect(item.security).toBe('external_encrypted_on_arrival');
    const opened = await alice.client.open(item.id);
    expect(opened.body?.text).toContain('نص');
    expect(opened.body?.attachments[0].name).toBe('تقرير.txt');
    expect(new TextDecoder().decode(await alice.client.downloadAttachment(opened.body!.attachments[0]))).toBe('attached content');
  });

  it('rejects unknown local recipients at RCPT time (no backscatter)', async () => {
    const err = await remote()
      .sendMail({ from: 'x@remote.example.org', to: `nobody-${uniq()}@voidmail.test`, subject: 's', text: 't' })
      .catch((e) => e);
    expect(err.responseCode).toBe(550);
  });

  it('is not an open relay', async () => {
    const err = await remote()
      .sendMail({ from: 'spammer@remote.example.org', to: 'victim@gmail.com', subject: 'relay?', text: 't' })
      .catch((e) => e);
    expect(err.responseCode).toBe(554);
    expect(String(err.response)).toMatch(/Relay access denied/i);
    // A forged local sender does not help.
    const err2 = await remote()
      .sendMail({ from: alice.address, to: 'victim@gmail.com', subject: 'relay?', text: 't' })
      .catch((e) => e);
    expect(err2.responseCode).toBe(554);
  });

  it('refuses submissions from networks other than the worker network', () => {
    const script = `
      const nm = require('nodemailer');
      nm.createTransport({ host: 'postfix', port: 10025, ignoreTLS: true })
        .sendMail({ envelope: { from: 'bounces+${'a'.repeat(32)}@voidmail.test', to: ['x@plain.example'] }, raw: 'Subject: x\\r\\n\\r\\nx' })
        .then(() => console.log('ACCEPTED'), (e) => console.log('REJECTED', e.responseCode));`;
    const out = compose(['exec', '-T', 'mx', 'node', '-e', script]);
    expect(out).toMatch(/REJECTED 554/);
  });

  it('the worker network may only use VoidMail bounce senders (no spoofed identities)', () => {
    const script = `
      const nm = require('nodemailer');
      nm.createTransport({ host: 'postfix', port: 10025, ignoreTLS: true })
        .sendMail({ envelope: { from: 'ceo@bank.example', to: ['x@plain.example'] }, raw: 'Subject: x\\r\\n\\r\\nx' })
        .then(() => console.log('ACCEPTED'), (e) => console.log('REJECTED', e.responseCode));`;
    const out = compose(['exec', '-T', 'worker', 'node', '-e', script]);
    expect(out).toMatch(/REJECTED 5\d\d/);
  });
});

describe('outbound SMTP (worker → Postfix → "remote" Mailpit)', () => {
  it('delivers standard email with honest label, strips Bcc, and records delivery', async () => {
    const subject = `outbound ${uniq()}`;
    const att = await alice.client.uploadAttachment('résumé.pdf', 'application/pdf', new TextEncoder().encode('%PDF-1.4 fake'));
    const res = await alice.client.send({
      to: ['someone@plain.example'],
      cc: [],
      bcc: ['hidden@plain.example'],
      subject,
      text: 'hello from voidmail',
      attachments: [att],
      requireTls: false,
    });
    expect(res.security).toBe('standard_tls_optional');
    const msgs = await waitFor(async () => {
      const r = await mailpitSearch(MAILPIT, `subject:"${subject}"`);
      return r.length ? r : null;
    });
    const raw = await mailpitRaw(MAILPIT, msgs[0].ID);
    // Mailpit (the receiving side) prepends its own Bcc: line derived from the SMTP envelope and a Received: trace
    // header ("for <rcpt>"). The message VoidMail transmitted starts at our first header, From:.
    const transmitted = raw.slice(raw.search(/^From: /m));
    expect(transmitted).not.toMatch(/^Bcc:/im);
    expect(transmitted).not.toContain('hidden@plain.example');
    expect(raw).toMatch(/^From: .*<.+@voidmail\.test>/m);
    expect(raw).toMatch(/^Return-Path: <bounces\+[0-9a-f]{32}@voidmail\.test>/m);
    expect(raw).not.toMatch(/Received: from .*172\.30\.1\./); // internal worker hop stripped
    expect(raw).toContain('filename');
    // The BCC recipient still got it (envelope only).
    const all = await mailpitSearch(MAILPIT, `subject:"${subject}"`);
    const rcpts = JSON.stringify(all);
    expect(rcpts).toContain('hidden@plain.example');
    // Postfix success DSN ("relayed") flows back through the bridge.
    const status = await waitFor(async () => {
      const d = await alice.client.delivery(res.id);
      return d.length && d.every((r: any) => r.status === 'delivered') ? d : null;
    }, 90_000, 2000);
    expect(status.map((s: any) => s.address).sort()).toEqual(['hidden@plain.example', 'someone@plain.example']);
  });

  it('uses STARTTLS opportunistically when the receiver offers it', async () => {
    const subject = `tls-opportunistic ${uniq()}`;
    await alice.client.send({ to: ['someone@tls.example'], cc: [], bcc: [], subject, text: 'x', attachments: [], requireTls: false });
    // mailpit-tls *requires* STARTTLS, so arrival proves the hop was encrypted.
    await waitFor(async () => (await mailpitSearch(MAILPIT_TLS, `subject:"${subject}"`)).length > 0);
    const logs = compose(['logs', '--since', '5m', 'postfix']);
    expect(logs).toMatch(/Anonymous TLS connection established to mailpit-tls|TLS connection established to mailpit-tls/);
  });

  it('Require-TLS delivers over TLS when available', async () => {
    const subject = `tls-required-ok ${uniq()}`;
    const res = await alice.client.send({ to: ['someone@tls.example'], cc: [], bcc: [], subject, text: 'x', attachments: [], requireTls: true });
    expect(res.security).toBe('standard_tls_required');
    await waitFor(async () => (await mailpitSearch(MAILPIT_TLS, `subject:"${subject}"`)).length > 0);
  });

  it('Require-TLS never falls back to plaintext; the failure is reported back to the sender', async () => {
    const subject = `tls-required-fail ${uniq()}`;
    const res = await alice.client.send({ to: ['nossl@plain.example'], cc: [], bcc: [], subject, text: 'must not arrive in clear', attachments: [], requireTls: true });
    // Postfix defers: the receiver does not offer STARTTLS.
    const entry = await waitFor(async () => {
      const q = queueJson().find((e) => e.recipients?.some((r: any) => r.address === 'nossl@plain.example' && /TLS/i.test(r.delay_reason ?? '')));
      return q ?? null;
    }, 90_000, 2000);
    expect(entry.recipients[0].delay_reason).toMatch(/TLS is required, but was not offered/i);
    expect(await mailpitSearch(MAILPIT, `subject:"${subject}"`)).toHaveLength(0);
    // Simulate the end of the retry period: expire and flush → Postfix bounces to the VERP address.
    compose(['exec', '-T', 'postfix', 'postsuper', '-e', entry.queue_id]);
    compose(['exec', '-T', 'postfix', 'postqueue', '-i', entry.queue_id]);
    const st = await waitFor(async () => {
      const d = await alice.client.delivery(res.id);
      return d[0]?.status === 'bounced' ? d : null;
    }, 90_000, 2000);
    expect(st[0].diagnostic).toMatch(/TLS/i);
    await findInbox(alice.client, 'Delivery failed');
    expect(await mailpitSearch(MAILPIT, `subject:"${subject}"`)).toHaveLength(0);
  });

  it('reports hard bounces from the remote side', async () => {
    // The plain Mailpit sink only accepts *.example recipients, so this address gets a real 5xx at RCPT.
    const subject = `bounce ${uniq()}`;
    const res = await alice.client.send({ to: ['user@hardbounce.test'], cc: [], bcc: [], subject, text: 'x', attachments: [], requireTls: false });
    const st = await waitFor(async () => {
      const d = await alice.client.delivery(res.id);
      return d[0]?.status === 'bounced' ? d : null;
    }, 90_000, 2000);
    expect(st[0].diagnostic).toMatch(/5\.\d\.\d/);
  });
});

describe('account recovery email through the real queue', () => {
  it('sends a reset link to the recovery address (and nothing for unknown users)', async () => {
    const carol = await newUser('carol', { recoveryEmail: `carol-${uniq()}@plain.example` });
    await carol.client.send({ to: [carol.address], cc: [], bcc: [], subject: 'before reset', text: 'x', attachments: [], requireTls: false });
    const { VoidClient } = await import('../../src/shared/client.js');
    const { fetchTransport } = await import('./live.js');
    const anon = new VoidClient(fetchTransport());
    await anon.requestEmailReset(carol.username);
    await anon.requestEmailReset('no-such-user-' + uniq());
    const mail = await waitFor(async () => {
      const r = await mailpitSearch(MAILPIT, `subject:"VoidMail account reset request" ${carol.username}`);
      return r.length ? r[0] : null;
    });
    const raw = (await mailpitRaw(MAILPIT, mail.ID)).replace(/=\r?\n/g, '');
    const token = /#\/reset\/([A-Za-z0-9_-]+)/.exec(raw)![1];
    await anon.completeEmailReset({ token, username: carol.username, newPassword: 'after email reset 1' });
    const items = (await anon.list({ folder: 'inbox' })).items;
    expect(items.find((i) => i.error === 'undecryptable')).toBeTruthy();
  });
});
