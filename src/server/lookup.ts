import net from 'node:net';
import type { Ctx } from './app.js';
import { resolveRecipient } from './inbound.js';

/** Postfix tcp_table(5) protocol for relay_recipient_maps: "get <urlencoded key>" -> "200 OK" / "500 no". */
export function lookupServer(ctx: Ctx): net.Server {
  return net.createServer((sock) => {
    sock.setEncoding('utf8');
    sock.setTimeout(30000, () => sock.destroy());
    let buf = '';
    sock.on('data', async (chunk: string) => {
      buf += chunk;
      if (buf.length > 4096) return sock.destroy();
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        const m = /^get (.+)$/.exec(line);
        if (!m) {
          sock.write('500 unsupported\n');
          continue;
        }
        try {
          const key = decodeURIComponent(m[1]);
          const found = key.includes('@') && !key.startsWith('@') ? await resolveRecipient(ctx, key) : null;
          sock.write(found ? '200 OK\n' : '500 not%20found\n');
        } catch {
          sock.write('400 temporary%20error\n');
        }
      }
    });
    sock.on('error', () => undefined);
  });
}
