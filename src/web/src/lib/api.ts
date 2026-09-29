import { VoidClient, type Transport } from '../../../shared/client';

/** Same-origin fetch transport. Cookies are HttpOnly; the CSRF token lives only in memory. */
const fetchTransport: Transport = async (method, path, opts = {}) => {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  let body: BodyInit | undefined;
  if (opts.bytes) body = opts.bytes as BodyInit;
  else if (opts.json !== undefined) {
    body = JSON.stringify(opts.json);
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  if (opts.binary && res.ok) return { status: res.status, data: null, bytes: new Uint8Array(await res.arrayBuffer()) };
  const ct = res.headers.get('content-type') ?? '';
  return { status: res.status, data: ct.includes('application/json') ? await res.json() : await res.text() };
};

export const client = new VoidClient(fetchTransport);

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function saveBytes(name: string, data: Uint8Array | string, type = 'application/octet-stream'): void {
  // Always download, never render inline: untrusted attachment content must not execute in our origin.
  const blob = new Blob([data as BlobPart], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
