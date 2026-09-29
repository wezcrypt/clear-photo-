import { describe, expect, it } from 'vitest';
import { isValidUsername, normalizeAddress, sanitizeFilename } from '../../src/shared/mail.js';
import { parseDeliveryStatus, extractDeliveryStatus } from '../../src/server/inbound.js';
import { parseBounceAddress, envelopeFrom } from '../../src/server/outbound.js';
import { ipPrefix } from '../../src/server/security.js';
import { backoffSeconds } from '../../src/server/worker.js';

describe('address validation', () => {
  it('normalizes valid addresses and rejects injection vectors', () => {
    expect(normalizeAddress(' Alice@VoidMail.Test ')).toBe('alice@voidmail.test');
    for (const bad of ['a@b', 'a b@c.com', 'a@b.com\r\nBcc: x@y.com', '"q"@x.com', 'a@b.com, c@d.com', '<a@b.com>', 'a@-b.com', 'a..b@c.com', '@x.com']) {
      expect(normalizeAddress(bad)).toBeNull();
    }
  });
  it('usernames', () => {
    expect(isValidUsername('alice.smith')).toBe(true);
    expect(isValidUsername('ab')).toBe(false);
    expect(isValidUsername('a..b')).toBe(false);
    expect(isValidUsername('Alice')).toBe(false);
    expect(isValidUsername('عربي')).toBe(false);
  });
});

describe('attachment filenames', () => {
  it('removes path traversal, control and bidi-spoofing characters', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('_.._etc_passwd'.replace(/^_/, '_'));
    expect(sanitizeFilename('invoice‮fdp.exe')).toBe('invoicefdp.exe');
    expect(sanitizeFilename('a\u0000b\nc.txt')).toBe('abc.txt');
    expect(sanitizeFilename('')).toBe('attachment');
    expect(sanitizeFilename('تقرير.pdf')).toBe('تقرير.pdf');
  });
});

describe('DSN parsing', () => {
  it('extracts per-recipient status from a delivery-status part', () => {
    const raw = 'Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx\r\n\r\nFinal-Recipient: rfc822; a@example.org\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 no such\r\n user\r\n\r\nFinal-Recipient: rfc822; b@example.org\r\nAction: delayed\r\nStatus: 4.4.1\r\n--boundary--';
    const part = extractDeliveryStatus(raw)!;
    const r = parseDeliveryStatus(part);
    expect(r).toEqual([
      { address: 'a@example.org', action: 'failed', status: '5.1.1', diagnostic: '550 5.1.1 no such user' },
      { address: 'b@example.org', action: 'delayed', status: '4.4.1', diagnostic: '' },
    ]);
  });
});

describe('misc', () => {
  it('VERP bounce addresses round-trip', () => {
    const cfg = { MAIL_DOMAIN: 'voidmail.test' } as never;
    const id = '0f0e0d0c-0b0a-4908-8706-050403020100';
    expect(parseBounceAddress(cfg, envelopeFrom(cfg, id, false))).toBe(id);
    expect(parseBounceAddress(cfg, envelopeFrom(cfg, id, true))).toBe(id);
    expect(parseBounceAddress(cfg, 'bounces+zz@voidmail.test')).toBeNull();
  });
  it('stores only IP prefixes', () => {
    expect(ipPrefix('203.0.113.77')).toBe('203.0.113.0/24');
    expect(ipPrefix('2001:db8:1234:5678::1')).toBe('2001:db8:1234::/48');
    expect(ipPrefix('::ffff:198.51.100.9')).toBe('198.51.100.0/24');
  });
  it('backoff grows and is capped', () => {
    expect(backoffSeconds(1)).toBeLessThan(backoffSeconds(3));
    expect(backoffSeconds(50)).toBe(14400);
  });
});
