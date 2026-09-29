import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import argon2 from 'argon2';
import { isIP } from 'node:net';
import type { Config } from './config.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../shared/crypto.js';

export function sha256(data: string | Uint8Array): Buffer {
  return createHash('sha256').update(data).digest();
}

export function hmac(key: Uint8Array, data: string): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Argon2id over an already high-entropy client-derived secret, with a server pepper. */
export async function hashSecret(cfg: Config, secret: Uint8Array): Promise<string> {
  return argon2.hash(Buffer.from(secret), {
    type: argon2.argon2id,
    memoryCost: cfg.ARGON2_MEMORY_KIB,
    timeCost: cfg.ARGON2_TIME,
    parallelism: 1,
    secret: cfg.keys.pepper,
  });
}

export async function verifySecret(cfg: Config, hash: string, secret: Uint8Array): Promise<boolean> {
  try {
    return await argon2.verify(hash, Buffer.from(secret), { secret: cfg.keys.pepper });
  } catch {
    return false;
  }
}

let dummyHash: string | null = null;
/** Burn comparable time for unknown users so timing does not reveal account existence. */
export async function dummyVerify(cfg: Config): Promise<void> {
  if (!dummyHash) dummyHash = await hashSecret(cfg, randomBytes(32));
  await verifySecret(cfg, dummyHash, randomBytes(32));
}

/** Store only a network prefix: /24 for IPv4, /48 for IPv6. */
export function ipPrefix(ip: string | undefined): string | null {
  if (!ip) return null;
  const v = isIP(ip);
  if (v === 4) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  if (v === 6) {
    if (ip.startsWith('::ffff:')) return ipPrefix(ip.slice(7));
    const parts = ip.split('::')[0].split(':');
    return parts.slice(0, 3).join(':') + '::/48';
  }
  return null;
}

export async function sealServer(key: Uint8Array, data: Uint8Array, aad: string): Promise<Buffer> {
  return Buffer.from(await aesGcmEncrypt(key, data, aad));
}

export async function openServer(key: Uint8Array, data: Uint8Array, aad: string): Promise<Buffer> {
  return Buffer.from(await aesGcmDecrypt(key, data, aad));
}

export function b64ToBuf(s: string): Buffer {
  return Buffer.from(s, 'base64');
}
