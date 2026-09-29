import { describe, expect, it } from 'vitest';
import * as C from '../../src/shared/crypto.js';

const weak: C.KdfParams = { alg: 'argon2id', m: 19456, t: 2, p: 1, v: 1 };

describe('shared crypto', () => {
  it('derives independent auth and wrap keys deterministically', async () => {
    const salt = C.randomBytes(16);
    const a = await C.deriveCredentials('pässwörd 🔐', salt, weak);
    const b = await C.deriveCredentials('pässwörd 🔐', salt, weak);
    expect(C.toB64(a.authKey)).toBe(C.toB64(b.authKey));
    expect(C.toB64(a.authKey)).not.toBe(C.toB64(a.wrapKey));
    const c = await C.deriveCredentials('pässwörd 🔐', C.randomBytes(16), weak);
    expect(C.toB64(c.authKey)).not.toBe(C.toB64(a.authKey));
  });

  it('refuses KDF parameters a malicious server could downgrade to', async () => {
    await expect(C.deriveMaster('x', C.randomBytes(16), { ...weak, m: 1024 })).rejects.toThrow(/too weak/);
    await expect(C.deriveMaster('x', C.randomBytes(16), { ...weak, t: 1 })).rejects.toThrow(/too weak/);
  });

  it('AES-GCM wrapping rejects tampering, wrong keys and wrong purpose (AAD)', async () => {
    const key = C.randomBytes(32);
    const mk = C.randomBytes(32);
    const blob = await C.aesGcmEncrypt(key, mk, C.AAD.mkPassword);
    expect(C.toB64(await C.aesGcmDecrypt(key, blob, C.AAD.mkPassword))).toBe(C.toB64(mk));
    const bad = blob.slice();
    bad[20] ^= 1;
    await expect(C.aesGcmDecrypt(key, bad, C.AAD.mkPassword)).rejects.toThrow();
    await expect(C.aesGcmDecrypt(C.randomBytes(32), blob, C.AAD.mkPassword)).rejects.toThrow();
    await expect(C.aesGcmDecrypt(key, blob, C.AAD.mkRecovery)).rejects.toThrow();
  });

  it('recovery keys round-trip and tolerate formatting', () => {
    const k = C.randomBytes(32);
    const text = C.encodeRecoveryKey(k);
    expect(text).toMatch(/^([A-Z0-9]{4}-){12}[A-Z0-9]{4}$/);
    expect(C.toB64(C.decodeRecoveryKey(text.toLowerCase().replace(/-/g, ' ')))).toBe(C.toB64(k));
    expect(() => C.decodeRecoveryKey('too-short')).toThrow();
  });

  it('OpenPGP payloads: sign/verify, wrong key, unknown signer, tamper', async () => {
    const mkA = C.randomBytes(32);
    const mkB = C.randomBytes(32);
    const a = await C.generateUserKey('a@voidmail.test', 'A', mkA);
    const b = await C.generateUserKey('b@voidmail.test', 'B', mkB);
    const aPriv = await C.unlockPrivateKey(a.privateKeyEnc, mkA);
    const bPriv = await C.unlockPrivateKey(b.privateKeyEnc, mkB);
    const aPub = await C.readPublicKey(a.publicKey);
    const bPub = await C.readPublicKey(b.publicKey);
    // private key cannot be unlocked with another Mailbox Key
    await expect(C.unlockPrivateKey(a.privateKeyEnc, mkB)).rejects.toThrow();
    const ct = await C.encryptJson({ s: 'سر' }, bPub, aPriv);
    const ok = await C.decryptJson<{ s: string }>(ct, [bPriv], [aPub]);
    expect(ok.value.s).toBe('سر');
    expect(ok.signature).toBe('valid');
    expect((await C.decryptJson(ct, [bPriv])).signature).toBe('unknown-key');
    expect((await C.decryptJson(ct, [bPriv], [bPub])).signature).not.toBe('valid');
    await expect(C.decryptJson(ct, [aPriv])).rejects.toThrow();
    const bad = ct.slice();
    bad[bad.length - 5] ^= 1;
    await expect(C.decryptJson(bad, [bPriv])).rejects.toThrow();
    expect(a.fingerprint).toMatch(/^[0-9a-f]{40}$/);
    expect(C.formatFingerprint(a.fingerprint).split(' ')).toHaveLength(10);
  });

  it('attachments: session-key encryption, wrong key and tamper rejected', async () => {
    const data = new TextEncoder().encode('attachment ✓');
    const { ciphertext, key } = await C.encryptAttachment(data);
    expect(new TextDecoder().decode(await C.decryptAttachment(ciphertext, key))).toBe('attachment ✓');
    await expect(C.decryptAttachment(ciphertext, C.toB64(C.randomBytes(32)))).rejects.toThrow();
    const bad = ciphertext.slice();
    bad[bad.length - 3] ^= 1;
    await expect(C.decryptAttachment(bad, key)).rejects.toThrow();
  });
});
