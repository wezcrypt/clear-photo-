import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildMime } from '../../src/server/outbound.js';

describe('outbound MIME', () => {
  it('is DKIM-signed when a key is configured, has no Bcc, and encodes Unicode safely', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const dir = mkdtempSync(path.join(os.tmpdir(), 'dkim-'));
    const file = path.join(dir, 'dkim.pem');
    writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const cfg = { MAIL_DOMAIN: 'voidmail.test', DKIM_SELECTOR: 'vm1', DKIM_PRIVATE_KEY_FILE: file } as never;
    const mime = (
      await buildMime(cfg, {
        from: { name: 'Ålice "Q"', address: 'alice@voidmail.test' },
        to: ['x@example.org'],
        cc: [],
        subject: 'مرحبا — hello',
        text: 'نص',
        attachments: [{ filename: 'تقرير.pdf', contentType: 'application/pdf', content: Buffer.from('x') }],
        messageId: '<id@voidmail.test>',
      })
    ).toString();
    expect(mime).toMatch(/^DKIM-Signature: v=1; a=rsa-sha256; c=relaxed\/relaxed; d=voidmail\.test;/m);
    expect(mime).toMatch(/s=vm1/);
    expect(mime).not.toMatch(/^Bcc:/im);
    expect(mime).toMatch(/^Subject: =\?UTF-8\?/m); // RFC 2047 encoded, no raw 8-bit header
  });
});
