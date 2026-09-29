// Cryptographic building blocks shared by the browser and the server.
// Everything here composes maintained primitives (OpenPGP.js, WebCrypto, hash-wasm Argon2id).
// See ENCRYPTION.md for the key hierarchy.
import * as openpgp from 'openpgp';
import { argon2id } from 'hash-wasm';

export interface KdfParams {
  alg: 'argon2id';
  m: number; // KiB
  t: number;
  p: number;
  v: 1;
}

export const DEFAULT_KDF: KdfParams = { alg: 'argon2id', m: 65536, t: 3, p: 1, v: 1 };

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const INFO = {
  auth: 'voidmail/v1/auth',
  wrap: 'voidmail/v1/wrap',
  recoveryAuth: 'voidmail/v1/recovery-auth',
  recoveryWrap: 'voidmail/v1/recovery-wrap',
  pgpPassphrase: 'voidmail/v1/pgp-passphrase',
} as const;

export const AAD = {
  mkPassword: 'voidmail/v1/mk/password',
  mkRecovery: 'voidmail/v1/mk/recovery',
} as const;

// ---------- encoding helpers ----------

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function toB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function toB64Url(bytes: Uint8Array): string {
  return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const B32 = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'; // Crockford-style, no I/L/O/U

/** Human-friendly encoding for the 32-byte recovery key: 52 chars in groups of 4. */
export function encodeRecoveryKey(bytes: Uint8Array): string {
  if (bytes.length !== 32) throw new Error('recovery key must be 32 bytes');
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out.match(/.{1,4}/g)!.join('-');
}

export function decodeRecoveryKey(text: string): Uint8Array {
  const clean = text
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (clean.length !== 52) throw new Error('invalid recovery key length');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('invalid recovery key character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out.slice(0, 32));
}

export function formatFingerprint(fp: string): string {
  return fp.toUpperCase().match(/.{1,4}/g)?.join(' ') ?? fp;
}

// ---------- KDF ----------

export async function deriveMaster(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  if (params.alg !== 'argon2id') throw new Error('unsupported kdf');
  // Guard against a malicious server downgrading the KDF cost.
  if (params.m < 19456 || params.t < 2 || params.p < 1) throw new Error('kdf parameters too weak');
  return argon2id({
    password: password.normalize('NFKC'),
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: 32,
    outputType: 'binary',
  });
}

export async function hkdf(ikm: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const key = await subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

export interface DerivedCredentials {
  authKey: Uint8Array;
  wrapKey: Uint8Array;
}

export async function deriveCredentials(password: string, salt: Uint8Array, params: KdfParams): Promise<DerivedCredentials> {
  const master = await deriveMaster(password, salt, params);
  const [authKey, wrapKey] = await Promise.all([hkdf(master, INFO.auth), hkdf(master, INFO.wrap)]);
  master.fill(0);
  return { authKey, wrapKey };
}

export async function deriveRecovery(recoveryKey: Uint8Array): Promise<{ recoveryAuth: Uint8Array; recoveryWrap: Uint8Array }> {
  const [recoveryAuth, recoveryWrap] = await Promise.all([
    hkdf(recoveryKey, INFO.recoveryAuth),
    hkdf(recoveryKey, INFO.recoveryWrap),
  ]);
  return { recoveryAuth, recoveryWrap };
}

// ---------- AES-256-GCM (key wrapping, server-side at-rest) ----------

export async function aesGcmEncrypt(keyBytes: Uint8Array, plaintext: Uint8Array, aad: string): Promise<Uint8Array> {
  if (keyBytes.length !== 32) throw new Error('AES-256 key required');
  const key = await subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: enc.encode(aad) }, key, plaintext as BufferSource),
  );
  const out = new Uint8Array(1 + iv.length + ct.length);
  out[0] = 1; // format version
  out.set(iv, 1);
  out.set(ct, 13);
  return out;
}

export async function aesGcmDecrypt(keyBytes: Uint8Array, blob: Uint8Array, aad: string): Promise<Uint8Array> {
  if (blob[0] !== 1 || blob.length < 13 + 16) throw new Error('unsupported ciphertext format');
  const key = await subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, ['decrypt']);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: blob.subarray(1, 13) as BufferSource, additionalData: enc.encode(aad) },
    key,
    blob.subarray(13) as BufferSource,
  );
  return new Uint8Array(pt);
}

// ---------- OpenPGP keys ----------

export async function pgpPassphrase(mailboxKey: Uint8Array): Promise<string> {
  return toB64Url(await hkdf(mailboxKey, INFO.pgpPassphrase));
}

export interface GeneratedKey {
  publicKey: string;
  privateKeyEnc: string;
  revocationCertificate: string;
  fingerprint: string;
}

export async function generateUserKey(email: string, name: string, mailboxKey: Uint8Array): Promise<GeneratedKey> {
  const passphrase = await pgpPassphrase(mailboxKey);
  const { publicKey, privateKey, revocationCertificate } = await openpgp.generateKey({
    type: 'curve25519',
    userIDs: [{ email, name: name || undefined }],
    passphrase,
    format: 'armored',
    config: { aeadProtect: true },
  });
  const key = await openpgp.readKey({ armoredKey: publicKey });
  return { publicKey, privateKeyEnc: privateKey, revocationCertificate, fingerprint: key.getFingerprint() };
}

export async function unlockPrivateKey(armored: string, mailboxKey: Uint8Array): Promise<openpgp.PrivateKey> {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: armored });
  return openpgp.decryptKey({ privateKey, passphrase: await pgpPassphrase(mailboxKey) });
}

export async function readPublicKey(armored: string): Promise<openpgp.Key> {
  return openpgp.readKey({ armoredKey: armored });
}

export async function fingerprintOf(armored: string): Promise<string> {
  return (await readPublicKey(armored)).getFingerprint();
}

// ---------- payload encryption ----------

export type SignatureStatus = 'valid' | 'invalid' | 'unsigned' | 'unknown-key';

export async function encryptJson(
  value: unknown,
  encryptionKeys: openpgp.Key | openpgp.Key[],
  signingKey?: openpgp.PrivateKey,
): Promise<Uint8Array> {
  const message = await openpgp.createMessage({ text: JSON.stringify(value) });
  return openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: signingKey,
    format: 'binary',
    config: { aeadProtect: true },
  }) as Promise<Uint8Array>;
}

export async function decryptJson<T>(
  data: Uint8Array,
  decryptionKeys: openpgp.PrivateKey[],
  verificationKeys?: openpgp.Key[],
): Promise<{ value: T; signature: SignatureStatus; signerKeyId?: string }> {
  const message = await openpgp.readMessage({ binaryMessage: data });
  const result = await openpgp.decrypt({
    message,
    decryptionKeys,
    verificationKeys: verificationKeys && verificationKeys.length ? verificationKeys : undefined,
    format: 'utf8',
  });
  let signature: SignatureStatus = 'unsigned';
  let signerKeyId: string | undefined;
  if (result.signatures.length > 0) {
    const sig = result.signatures[0];
    signerKeyId = sig.keyID.toHex();
    if (!verificationKeys || verificationKeys.length === 0) {
      signature = 'unknown-key';
    } else {
      try {
        await sig.verified;
        signature = 'valid';
      } catch (e) {
        signature = /Could not find signing key/i.test(String((e as Error).message)) ? 'unknown-key' : 'invalid';
      }
    }
  }
  return { value: JSON.parse(result.data as string) as T, signature, signerKeyId };
}

// ---------- attachment encryption (per-attachment session key, SEIPDv2) ----------

export async function encryptAttachment(data: Uint8Array): Promise<{ ciphertext: Uint8Array; key: string }> {
  const keyBytes = randomBytes(32);
  const ciphertext = (await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: data }),
    sessionKey: { data: keyBytes, algorithm: 'aes256', aeadAlgorithm: 'gcm' },
    format: 'binary',
    config: { aeadProtect: true },
  })) as Uint8Array;
  return { ciphertext, key: toB64(keyBytes) };
}

export async function decryptAttachment(ciphertext: Uint8Array, key: string): Promise<Uint8Array> {
  const message = await openpgp.readMessage({ binaryMessage: ciphertext });
  const { data } = await openpgp.decrypt({
    message,
    sessionKeys: { data: fromB64(key), algorithm: 'aes256', aeadAlgorithm: 'gcm' },
    format: 'binary',
  });
  return data as Uint8Array;
}

export { openpgp, enc as utf8Encoder, dec as utf8Decoder };
