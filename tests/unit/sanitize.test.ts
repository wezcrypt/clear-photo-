import { describe, expect, it } from 'vitest';
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';
import { frameDocument, makeSanitizer } from '../../src/web/src/lib/sanitize.js';

const window = new JSDOM('').window;
const sanitize = makeSanitizer(createDOMPurify(window as unknown as Window & typeof globalThis) as never);

describe('email HTML sanitizer', () => {
  it('removes scripts, event handlers and active content', () => {
    const { html } = sanitize(
      `<p onclick="x()">hi</p><script>alert(1)</script><img src=x onerror=alert(1)><iframe src="https://e.x"></iframe>
       <object data="x"></object><embed src="x"><form action="https://e.x"><input name=p></form><svg><script>1</script></svg>
       <a href="javascript:alert(1)">js</a><meta http-equiv="refresh" content="0;url=https://e.x"><base href="https://e.x/">
       <math><mi>x</mi></math><button formaction="https://e.x">b</button>`,
      { allowRemote: false },
    );
    expect(html).not.toMatch(/<script|onerror|onclick|<iframe|<object|<embed|<form|<input|<svg|javascript:|<meta|<base|<math|<button/i);
    expect(html).toContain('hi');
  });

  it('blocks remote images and tracking pixels by default and counts them', () => {
    const r = sanitize(
      `<img src="https://tracker.example/p.gif" width=1 height=1><img src="http://x.example/a.png"><img src="//x.example/b.png">
       <div style="background:url(https://t.example/bg.png)">x</div><td background="https://t.example/td.png"></td>
       <style>@import url(https://t.example/a.css); .a{background-image:url('https://t.example/c.png')}</style>
       <img srcset="https://t.example/s.png 1x">`,
      { allowRemote: false },
    );
    expect(r.html).not.toMatch(/https?:\/\/(tracker|x|t)\.example/);
    expect(r.blocked).toBeGreaterThanOrEqual(6);
  });

  it('allows https images only after explicit consent, never http', () => {
    const r = sanitize(`<img src="https://cdn.example/a.png"><img src="http://cdn.example/b.png">`, { allowRemote: true });
    expect(r.html).toContain('https://cdn.example/a.png');
    expect(r.html).toContain('referrerpolicy="no-referrer"');
    expect(r.html).not.toContain('http://cdn.example/b.png');
  });

  it('maps cid: inline images to provided data URLs', () => {
    const r = sanitize(`<img src="cid:logo@x">`, { allowRemote: false, inline: { 'logo@x': 'data:image/png;base64,AAAA' } });
    expect(r.html).toContain('data:image/png;base64,AAAA');
    expect(r.blocked).toBe(0);
  });

  it('forces safe link targets and flags deceptive link text', () => {
    const r = sanitize(`<a href="https://evil.example/login">https://mybank.com</a> <a href="https://docs.example.org/x">docs.example.org</a>`, {
      allowRemote: false,
    });
    expect(r.html).toContain('rel="noopener noreferrer nofollow"');
    expect(r.html).toContain('target="_blank"');
    expect(r.mismatchedLinks).toEqual([{ text: 'https://mybank.com', href: 'https://evil.example/login' }]);
  });

  it('keeps Arabic text and formatting', () => {
    const r = sanitize('<p dir="rtl" style="color:red"><b>مرحبا</b> بالعالم</p>', { allowRemote: false });
    expect(r.html).toContain('<b>مرحبا</b>');
    expect(r.html).toContain('dir="rtl"');
  });

  it('frame document carries a restrictive CSP', () => {
    const doc = frameDocument('<p>x</p>', { allowRemote: false });
    expect(doc).toContain("default-src 'none'; img-src data:;");
    expect(frameDocument('', { allowRemote: true })).toContain('img-src data: https:');
  });
});
