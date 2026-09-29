// Untrusted email HTML → safe HTML for a sandboxed, script-less iframe.
// Defence in depth: (1) DOMPurify with a strict allow-list, (2) remote resources rewritten/blocked,
// (3) iframe sandbox without allow-scripts/allow-same-origin, (4) a CSP meta inside the frame document.
import DOMPurify, { type DOMPurify as DOMPurifyInstance } from 'dompurify';

export interface SanitizeResult {
  html: string;
  blocked: number;
  mismatchedLinks: { text: string; href: string }[];
}

export interface SanitizeOptions {
  allowRemote: boolean;
  /** cid → data: URL for inline images */
  inline?: Record<string, string>;
}

const FORBID_TAGS = [
  'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'meta', 'link', 'form', 'input',
  'button', 'textarea', 'select', 'option', 'svg', 'math', 'audio', 'video', 'source', 'track', 'canvas', 'template',
  'portal', 'noscript', 'dialog',
];
const FORBID_ATTR = ['srcset', 'action', 'formaction', 'ping', 'background', 'poster', 'xlink:href', 'lowsrc', 'dynsrc', 'longdesc', 'autofocus'];
const URL_IN_CSS = /url\s*\(\s*(['"]?)(.*?)\1\s*\)/gi;
const IMPORT_IN_CSS = /@import[^;]*;?/gi;

function hostOf(u: string): string | null {
  try {
    return new URL(u).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

/** Visible link text that itself looks like a URL or domain. */
function textHost(text: string): string | null {
  const s = text.trim();
  const m = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i.exec(s);
  return m ? m[1].toLowerCase().replace(/^www\./, '') : null;
}

export function makeSanitizer(purify: DOMPurifyInstance = DOMPurify) {
  return function sanitizeEmailHtml(input: string, opts: SanitizeOptions): SanitizeResult {
    let blocked = 0;
    const mismatchedLinks: SanitizeResult['mismatchedLinks'] = [];

    const rewriteCss = (css: string): string =>
      css.replace(IMPORT_IN_CSS, () => {
        blocked++;
        return '';
      }).replace(URL_IN_CSS, (_m, _q, url: string) => {
        const u = url.trim();
        if (/^data:image\//i.test(u)) return `url("${u.replace(/"/g, '')}")`;
        if (/^cid:/i.test(u) && opts.inline?.[u.slice(4)]) return `url("${opts.inline[u.slice(4)]}")`;
        if (opts.allowRemote && /^https:\/\//i.test(u)) return `url("${u.replace(/["\\]/g, '')}")`;
        blocked++;
        return 'none';
      });

    purify.addHook('uponSanitizeElement', (node, data) => {
      if (data.tagName === 'style' && node.textContent) node.textContent = rewriteCss(node.textContent);
    });
    purify.addHook('uponSanitizeAttribute', (_node, data) => {
      if (['srcset', 'background', 'poster', 'lowsrc', 'dynsrc'].includes(data.attrName) && /(https?:)?\/\//i.test(data.attrValue)) blocked++;
    });
    purify.addHook('afterSanitizeAttributes', (node) => {
      const el = node as Element;
      if (el.hasAttribute('style')) el.setAttribute('style', rewriteCss(el.getAttribute('style') ?? ''));
      if (el.tagName === 'IMG') {
        const src = (el.getAttribute('src') ?? '').trim();
        if (/^cid:/i.test(src)) {
          const data = opts.inline?.[src.slice(4)];
          if (data) el.setAttribute('src', data);
          else el.removeAttribute('src');
        } else if (/^data:image\/(png|gif|jpe?g|webp);/i.test(src)) {
          // inline data images are fine
        } else if (opts.allowRemote && /^https:\/\//i.test(src)) {
          el.setAttribute('referrerpolicy', 'no-referrer');
          el.setAttribute('loading', 'lazy');
        } else if (src) {
          blocked++;
          el.removeAttribute('src');
          el.setAttribute('data-blocked', '1');
          el.setAttribute('alt', el.getAttribute('alt') || '');
        }
      }
      if (el.tagName === 'A') {
        const href = (el.getAttribute('href') ?? '').trim();
        if (!/^(https?:|mailto:)/i.test(href)) {
          el.removeAttribute('href');
        } else {
          el.setAttribute('target', '_blank');
          el.setAttribute('rel', 'noopener noreferrer nofollow');
          const shown = textHost(el.textContent ?? '');
          const real = hostOf(href);
          if (shown && real && shown !== real && !real.endsWith('.' + shown)) {
            mismatchedLinks.push({ text: (el.textContent ?? '').trim().slice(0, 120), href: href.slice(0, 300) });
            el.setAttribute('title', `⚠ ${href}`);
          } else {
            el.setAttribute('title', href);
          }
        }
      }
    });
    try {
      const html = purify.sanitize(input, {
        FORBID_TAGS,
        FORBID_ATTR,
        ALLOW_DATA_ATTR: false,
        ALLOW_UNKNOWN_PROTOCOLS: false,
        ADD_TAGS: ['style'],
        ADD_ATTR: ['dir', 'lang', 'align', 'valign', 'bgcolor', 'cellpadding', 'cellspacing'],
        FORCE_BODY: true,
        WHOLE_DOCUMENT: false,
        SANITIZE_DOM: true,
        // Same shape as DOMPurify's default (scheme-less values such as dir="rtl" pass) with a narrower scheme list.
        // URL-bearing attributes are further restricted by the hooks above.
        ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|cid):|data:image\/(?:png|gif|jpe?g|webp);|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
      }) as unknown as string;
      return { html, blocked, mismatchedLinks };
    } finally {
      purify.removeAllHooks();
    }
  };
}

/** Wraps sanitized HTML in a document with its own restrictive CSP (the iframe also inherits the app CSP). */
export function frameDocument(bodyHtml: string, opts: { allowRemote: boolean }): string {
  const img = opts.allowRemote ? 'data: https:' : 'data:';
  const csp = `default-src 'none'; img-src ${img}; style-src 'unsafe-inline'; font-src 'none'; media-src 'none'; form-action 'none'`;
  return `<!doctype html><html dir="auto"><head><meta http-equiv="Content-Security-Policy" content="${csp}"><meta name="referrer" content="no-referrer"><base target="_blank"><style>
html,body{margin:0;padding:0;background:#fff;color:#1a1a1f;font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;word-wrap:break-word;overflow-wrap:anywhere}
body{padding:16px}img{max-width:100%;height:auto}img[data-blocked]{display:inline-block;min-width:16px;min-height:16px;background:#eee;outline:1px dashed #bbb}
table{max-width:100%}pre{white-space:pre-wrap}a{color:#5b3fd6}
</style></head><body>${bodyHtml}</body></html>`;
}
