// Payload formats and address validation shared by browser and server.

/** Encrypted "header" payload: what the mailbox list needs. */
export interface HeaderPayload {
  v: 1;
  subject: string;
  from: { name: string; address: string };
  to: string[];
  cc: string[];
  /** Only present in the sender's own copy. */
  bcc?: string[];
  date: string;
  snippet: string;
  hasAttachments: boolean;
  /** Random value repeated in the body payload; binds header and body of one message together. */
  nonce?: string;
}

export interface AttachmentRef {
  id: string;
  name: string;
  type: string;
  size: number;
  /** base64 session key for the attachment ciphertext */
  key: string;
  /** Content-ID for inline images referenced as cid: in HTML */
  cid?: string;
}

/** Encrypted "body" payload. */
export interface BodyPayload {
  v: 1;
  text: string;
  html?: string;
  attachments: AttachmentRef[];
  /** Selected original headers for external mail (informational). */
  headers?: Record<string, string>;
  /** For drafts: mode and reply context. */
  draft?: { requireTls: boolean; inReplyTo?: string; references?: string[] };
  nonce?: string;
}

export type SecurityLabel =
  | 'e2ee'
  | 'external_encrypted_on_arrival'
  | 'standard_tls_optional'
  | 'standard_tls_required'
  | 'draft'
  | 'system';

export const FOLDERS = ['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash'] as const;
export type Folder = (typeof FOLDERS)[number];

// Deliberately conservative: ASCII local parts, standard domain syntax.
// Rejects quoted local parts, comments, whitespace and control characters (header-injection defence).
const LOCAL = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DOMAIN = /^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

export function normalizeAddress(input: string): string | null {
  const s = input.trim();
  if (s.length > 254 || /[\s\r\n<>(),;:"\\]/.test(s)) return null;
  const at = s.lastIndexOf('@');
  if (at <= 0 || at === s.length - 1) return null;
  const local = s.slice(0, at);
  const domain = s.slice(at + 1).toLowerCase();
  if (local.length > 64 || !LOCAL.test(local) || !DOMAIN.test(domain)) return null;
  return `${local.toLowerCase()}@${domain}`;
}

export const USERNAME_RE = /^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])$/;

export function isValidUsername(u: string): boolean {
  return USERNAME_RE.test(u) && !/[._-]{2}/.test(u);
}

/** Strip characters that can spoof filenames or traverse paths. */
export function sanitizeFilename(name: string): string {
  const cleaned = name
    // control chars, bidi overrides/isolates, zero-width chars
    .replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
    .replace(/[/\\:*?"<>|]/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 200);
  return cleaned || 'attachment';
}

export function makeSnippet(text: string, max = 140): string {
  return text.replace(/\s+/g, ' ').trim().slice(0, max);
}
