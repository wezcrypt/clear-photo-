// Local, in-memory search over decrypted mail. Nothing is persisted or sent to the server.
import type { ListItem } from '../../../shared/client';

const TASHKEEL = /[ؐ-ًؚ-ٰٟۖ-ۭـ]/g;

export function normalize(s: string): string {
  return s
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(TASHKEEL, '')
    .replace(/[إأآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه');
}

export class LocalIndex {
  private docs = new Map<string, { item: ListItem; text: string }>();

  add(item: ListItem, bodyText = ''): void {
    const h = item.header;
    if (!h) return;
    const prev = this.docs.get(item.id);
    const text = normalize([h.subject, h.from.name, h.from.address, ...h.to, ...h.cc, h.snippet, bodyText || prev?.text || ''].join(' '));
    this.docs.set(item.id, { item, text });
  }

  has(id: string): boolean {
    return this.docs.has(id);
  }

  get size(): number {
    return this.docs.size;
  }

  search(query: string): ListItem[] {
    const terms = normalize(query).split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    const out: ListItem[] = [];
    for (const { item, text } of this.docs.values()) if (terms.every((t) => text.includes(t))) out.push(item);
    return out.sort((a, b) => b.receivedAt.localeCompare(a.receivedAt));
  }

  clear(): void {
    this.docs.clear();
  }
}

export const localIndex = new LocalIndex();
