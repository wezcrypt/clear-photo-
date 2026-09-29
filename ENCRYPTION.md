# VoidMail Encryption Design

All cryptographic primitives come from maintained libraries:

- **OpenPGP.js 6** (RFC 9580) — key generation, public-key encryption, signatures, AEAD (SEIPDv2, AES-256 + GCM/OCB).
- **WebCrypto** (browser/Node built-in) — HKDF-SHA-256, AES-256-GCM for Mailbox-Key wrapping, CSPRNG.
- **hash-wasm** — Argon2id in the browser.
- **argon2** (node-argon2, reference C implementation) — Argon2id on the server.

No custom ciphers, MACs or protocols are implemented. The implementation lives in `src/shared/crypto.ts` (shared by browser and server) and is covered by `tests/unit/crypto.test.ts`.

## 1. Key hierarchy

```
password ──Argon2id(salt, 64 MiB, t=3, p=1)──► master (32 B, browser only)
   master ──HKDF "voidmail/v1/auth"──► authKey  ──► sent to server ──► Argon2id(authKey, pepper) stored
   master ──HKDF "voidmail/v1/wrap"──► wrapKey  (AES-256-GCM, never leaves browser)

recoveryKey (32 random bytes, shown once as 13 groups of base32)
   ──HKDF "voidmail/v1/recovery-auth"──► recoveryAuth ──► Argon2id(…, pepper) stored
   ──HKDF "voidmail/v1/recovery-wrap"──► recoveryWrap (AES-256-GCM)

Mailbox Key MK (32 random bytes, browser only when unlocked)
   stored as  AES-GCM(wrapKey,     MK, aad="voidmail/v1/mk/password")
   and        AES-GCM(recoveryWrap, MK, aad="voidmail/v1/mk/recovery")

MK ──HKDF "voidmail/v1/pgp-passphrase"──► passphrase for every OpenPGP private key of the account
   OpenPGP private key (Curve25519, v4 key, AEAD feature flags) stored encrypted by OpenPGP S2K with that passphrase
```

Consequences:

- **Changing the password** re-wraps MK only. Keys and mail are untouched.
- **Rotating the OpenPGP key** needs MK only (no recovery key re-entry).
- **The server never receives** the password, `master`, `wrapKey`, MK, `recoveryKey`, `recoveryWrap`, or any decrypted private key.
- **Account credentials and mailbox keys are separated**: the server can verify `authKey` but cannot derive `wrapKey` from it (independent HKDF outputs of a secret the server never sees).

## 2. Key lifecycle

| Operation | Implementation |
|---|---|
| Generation | At registration, in the browser: `openpgp.generateKey({type:'curve25519', config:{aeadProtect:true}})`. |
| Wrapping | Private key encrypted with OpenPGP S2K using the MK-derived passphrase; MK wrapped twice (password, recovery). |
| Unlocking | Login → derive wrapKey → unwrap MK → decrypt private keys in memory. Reloading the page requires unlocking again (MK is not persisted in browser storage). |
| Synchronization across devices | All devices download the same wrapped blobs and unlock with the password. Adding a device never uploads a key in plaintext and never downgrades to server-readable mail. |
| Rotation | Settings → Security → "Rotate encryption key": new key generated in the browser, becomes `active`; old key becomes `retired` (still used to decrypt old mail, never for new mail). Contacts see a key-change warning. |
| Revocation | Rotation publishes the new key only. Retired keys are never served by the key directory. (OpenPGP revocation certificates are generated and stored encrypted, but publication to external keyservers is not implemented.) |
| Recovery with recovery key | See §5. |
| Loss | If both password and recovery key are lost, MK cannot be recovered by anyone, including VoidMail. See §5. |

## 3. Message encryption

### Internal (VoidMail → VoidMail): end-to-end

For each message the browser:

1. Generates a random 256-bit session key per attachment and encrypts each attachment once with OpenPGP SEIPDv2 (`sessionKey` mode). The ciphertext is uploaded; the server never sees the key.
2. Builds two JSON payloads: **header** (`subject, from, to, cc, date, snippet, hasAttachments`) and **body** (`text, html, attachments[{id, name, type, size, key}]`).
3. Encrypts and **signs** header and body *separately for each recipient* (one PKESK per ciphertext) and once more for the sender's Sent copy. Separate encryption means a recipient's ciphertext carries no key IDs of other (e.g. BCC) recipients. BCC addresses appear only in the sender's own copy.
4. Sends ciphertexts to the API, which stores them per mailbox. The API validates addresses, attachment ownership and quotas; it cannot validate content.

On reading, the browser decrypts with the recipient's keys and verifies the signature against the sender's public key from the directory, subject to pinning (§4). Tampered ciphertext fails AEAD authentication and is shown as "Could not decrypt", never as partial content.

### External inbound: encrypted after arrival

The `mx-bridge` process encrypts the parsed message to the recipient's active public key with the same payload format (unsigned; attachments use per-attachment session keys generated server-side). The server had the plaintext; see SECURITY_ARCHITECTURE.md §5.

### External outbound: standard email

The browser sends the plaintext (and, for attachments, the per-attachment session keys) to the API over HTTPS for that single send. The API:

- stores the Sent copy encrypted by the browser to the sender's own key,
- builds MIME with `nodemailer`'s MailComposer, DKIM-signs it, encrypts the MIME with AES-256-GCM (`QUEUE_KEY`, server-held) into the `outbound_queue` row,
- the worker decrypts it only to hand it to Postfix and deletes the payload once Postfix accepts it.

This is server-side encryption, **not** E2EE, and is labelled so.

### Drafts

Drafts are encrypted in the browser to the author's own key before each autosave (every 3 s after changes). Recipient lists of drafts are inside the ciphertext.

## 4. Public-key discovery and verification (trust model)

- The key directory (`GET /api/keys/lookup?address=`) is served by VoidMail. **A malicious server can return a substituted key.** VoidMail does not claim otherwise.
- Mitigation implemented: **trust-on-first-use pinning**. The first time you write to or read from an address, its key fingerprint is pinned in your *vault* (a JSON document encrypted to your own key and signed by it, stored on the server; the server cannot read or forge it, but could roll it back to an older version).
- If the directory later returns a different fingerprint, the compose screen blocks E2EE sending to that address and shows a **key-change warning** with old and new fingerprints until you accept the change.
- **Explicit verification**: every contact's fingerprint (and your own, in Settings) is displayed in groups of 4 hex characters. After comparing it with the person out-of-band (in person, phone, another secure channel) you mark it "Verified". Verified contacts show a distinct badge; a key change downgrades them to unverified and warns.
- Only keys whose fingerprint you verified out-of-band are protected against substitution by a malicious server at first contact.

## 5. Recovery

**Account recovery ≠ recovery of encrypted mail.**

| Situation | What happens |
|---|---|
| Forgot password, **have recovery key** | Browser proves possession (`recoveryAuth`), receives the recovery-wrapped MK, unwraps it locally, sets a new password (re-wraps MK), receives a fresh recovery key. All sessions revoked. **All mail stays readable.** |
| Forgot password, **no recovery key**, recovery email configured | A reset link (single-use, 30-minute, hashed token) is emailed. After reset, a **new** MK and a **new** key pair are created. Old mail remains stored but is **permanently unreadable** — the UI requires typing a confirmation before proceeding. |
| Forgot password, no recovery key, no recovery email | No recovery. The account cannot be regained. |
| Know password, lost recovery key | Settings → Security → "Regenerate recovery key" (requires unlocked mailbox). The old recovery key stops working. |

Recovery key alone is sufficient to reset the password (2FA is not required for recovery-key resets, because the recovery key is itself a 256-bit secret). Store it offline.

## 6. What is authenticated

- Message ciphertexts: AEAD (SEIPDv2) — any modification is rejected.
- Message origin (internal): OpenPGP signature by sender key, verified against the pinned key.
- MK wraps: AES-GCM with purpose-bound AAD.
- Queue payloads: AES-GCM with the queue row id as AAD.
- TOTP secrets: AES-GCM with the user id as AAD.
- External inbound mail: **not** signed by the sender; authenticity depends on SMTP-level checks, which are not yet implemented in VoidMail (see README risks).
