# VoidMail Threat Model

Status: living document, written before implementation and updated to match the code.
It has **not** been reviewed by an independent auditor.

## 1. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Message bodies, subjects, attachments | Postgres `messages.header_enc/body_enc` (OpenPGP ciphertext), blob store (ciphertext) | High |
| User OpenPGP private keys | Postgres `user_keys.private_key_enc` (encrypted with a key derived from the Mailbox Key) | Critical |
| Mailbox Key (MK) | Only in browser memory; stored wrapped (AES-256-GCM) by password-derived key and by recovery key | Critical |
| Login password | Only in the browser; never sent to the server | Critical |
| Auth verifier | Postgres `users.auth_hash` (Argon2id of a client-derived key, with server pepper) | High |
| Session tokens | Browser cookie (HttpOnly); server stores SHA-256 hash only | High |
| TOTP secrets | Postgres, AES-256-GCM encrypted with a server key | High |
| Metadata (who mailed whom, when, sizes, folders, flags, labels) | Postgres, plaintext | Medium–High |
| External outbound mail in flight | Queue table (AES-GCM, server key), Postfix spool (plaintext, transient) | High |
| Inbound external mail in flight | Postfix spool (plaintext, transient), inbound bridge memory | High |
| DKIM private key, server secrets | Environment / mounted files | Critical |

## 2. Trust boundaries

1. **Browser ↔ VoidMail web/API** (HTTPS). The browser runs JavaScript served by VoidMail.
2. **API ↔ Postgres / blob store** (private network).
3. **Postfix ↔ Internet** (SMTP on port 25, opportunistic or mandatory TLS).
4. **Postfix ↔ inbound bridge** (LMTP, private network), **worker ↔ Postfix submission** (private network, restricted by `mynetworks`).
5. **Operator ↔ servers** (SSH, admin CLI).
6. **User ↔ recipient** (humans, recipient devices, remote mail providers).

## 3. Adversaries and what they get

| Adversary | Capability | Outcome with current design |
|---|---|---|
| **Database thief** (stolen dump, SQL injection read) | Reads all tables | Gets metadata (addresses, timestamps, sizes, folders, label names, sender/recipient envelope addresses). Gets ciphertext of all message bodies/subjects/attachments. Gets Argon2id verifiers of *client-derived* keys (offline guessing requires Argon2id client-side cost **and** the server pepper, which is not in the DB). Cannot read mail without cracking a user password or holding a recovery key. |
| **Backup thief** | Reads encrypted backup file | Nothing without the backup passphrase. If backup passphrase also stolen: same as DB thief. |
| **Blob-store thief** | Reads attachment objects | Ciphertext only; keys live inside per-user encrypted message bodies. |
| **Malicious administrator / insider (passive)** | Reads DB, logs, queues | Metadata, plus **plaintext of external mail at arrival/departure** (spool, bridge memory, queue key). Cannot read stored internal E2EE mail or previously stored mail. |
| **Compromised server (active)** | Modifies code, serves JS, swaps keys | Can serve malicious JavaScript that exfiltrates the password or Mailbox Key the next time a user logs in. Can substitute public keys returned by the key directory (mitigated only by fingerprint pinning, key-change warnings and manual verification). Can read all future external mail. **Browser E2EE does not protect against an actively malicious server.** |
| **Network attacker** (between browser and VoidMail) | Intercepts traffic | Blocked by HTTPS + HSTS in production. Local dev runs HTTP on localhost only. |
| **Network attacker** (between MTAs) | Intercepts SMTP | Opportunistic TLS can be downgraded (STARTTLS stripping). MTA-STS / DANE and the "Require TLS" sending mode reduce this. Metadata of SMTP envelope visible to relays. |
| **XSS via email content** | Crafted HTML email | Mitigated: DOMPurify sanitization, rendering in a sandboxed `srcdoc` iframe without `allow-scripts` or `allow-same-origin`, strict app CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline scripts), remote content blocked by default. |
| **Account takeover** (credential stuffing, phishing) | Guesses/steals password | Argon2id, per-IP and per-account rate limits, optional TOTP + recovery codes, session list and revocation. Phishing of password + TOTP is **not** prevented (no passkeys yet). |
| **Phishing via mail** | Look-alike senders, deceptive links | Security labels distinguish internal E2EE vs external mail; links open with `noopener noreferrer`; link text/href mismatch warning; SPF/DKIM/DMARC evaluation is **not implemented yet** (see risks). |
| **Spammer / abuser with an account** | Bulk sending | Per-user daily and per-minute send limits, recipients-per-message cap, account suspension via admin CLI. |
| **Open-relay abuser** | Connects to port 25 | Postfix `reject_unauth_destination`; only VoidMail domains accepted; unknown recipients rejected at RCPT via recipient lookup; submission listener only accepts the worker's private network. Tested. |
| **Device compromise** | Malware on user's device | Out of scope: it can read decrypted mail, keystrokes, and the in-memory Mailbox Key. |
| **Recipient** | Receives your message | Can forward, screenshot, or leak. E2EE ends at the recipient. External recipients' providers can read standard email. |

## 4. Assumptions

- The TLS certificate and HTTPS termination for the web app are correctly configured in production.
- The code users run is the code in this repository. There is currently **no** mechanism (e.g. browser extension, reproducible build verification, signed web bundles) that lets users verify this.
- Server secrets (`APP_SECRET`, `AUTH_PEPPER`, `QUEUE_KEY`, `TOTP_KEY`, DKIM key) are kept out of the database and backups.
- Users choose passwords that resist offline guessing. The client requires ≥ 10 characters; there is no strength meter or breached-password check.
- Operating-system, Postgres, Postfix and Node.js are patched.

## 5. Explicit non-goals / limits

- Anonymity. VoidMail sees the IP address of connections (not stored long-term, see PRIVACY.md) and mail metadata.
- Protecting external standard email from VoidMail's servers at the moment of receipt or sending.
- Hiding the envelope (who talks to whom, when, sizes) from VoidMail for internal mail.
- Protection against a compromised server that serves modified JavaScript.
- Protection against a compromised end-user device.
- Revoking copies already delivered or downloaded.

See SECURITY_ARCHITECTURE.md for the concrete design and ENCRYPTION.md for cryptographic details.
