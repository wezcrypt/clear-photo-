import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

/**
 * Stores opaque ciphertext objects. The store never sees plaintext or keys.
 * A filesystem driver is implemented; an S3-compatible driver can implement the same interface
 * (see DEPLOYMENT.md). Keys are random UUIDs and never derived from user data.
 */
export interface BlobStore {
  put(data: Uint8Array): Promise<string>;
  get(key: string): Promise<Buffer>;
  delete(key: string): Promise<void>;
}

const KEY_RE = /^[0-9a-f-]{36}$/;

export class FsBlobStore implements BlobStore {
  constructor(private readonly root: string) {}

  private file(key: string): string {
    if (!KEY_RE.test(key)) throw new Error('invalid blob key');
    return path.join(this.root, key.slice(0, 2), key.slice(2, 4), key);
  }

  async put(data: Uint8Array): Promise<string> {
    const key = randomUUID();
    const target = this.file(key);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const tmp = `${target}.tmp`;
    await writeFile(tmp, data, { mode: 0o600 });
    await rename(tmp, target);
    return key;
  }

  async get(key: string): Promise<Buffer> {
    return readFile(this.file(key));
  }

  async delete(key: string): Promise<void> {
    await rm(this.file(key), { force: true });
  }
}
