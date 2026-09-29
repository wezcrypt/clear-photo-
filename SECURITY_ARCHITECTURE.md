# VoidMail Security Architecture

This document describes what VoidMail protects, how, and — equally important — what it does **not** protect.
It is written to match the implementation in this repository. It is not an independent audit.
Threat actors and assumptions are in [THREAT_MODEL.md](THREAT_MODEL.md); key handling is in [ENCRYPTION.md](ENCRYPTION.md).

## 1. Three different kinds of "encryption"

VoidMail uses three distinct protections. The interface never uses one label for another.

| Term | What it means | Who can read the content |
|---|---|---|
| **Transport encryption** (TLS) | Content is encrypted while travelling between two machines (browser↔VoidMail, VoidMail↔another mail server). | Both endpoints of each hop, including VoidMail and the remote provider. |
| **Server-side encryption at rest** | Content is stored encrypted, but the server held the plaintext at some moment (e.g. when external email arrived) or holds a key. | The server at processing time; anyone controlling the server afterwards for new mail. |
| **End-to-end encryption (E2EE)** | Content is encrypted in the sender's browser to keys whose private halves only the recipients' browsers can unlock. | Only the sender and recipients (subject to the browser-JavaScript limit in §6). |

## 2. Components and separation

```
 Browser (React SPA, OpenPGP.js, Argon2id-wasm)
   │  HTTPS (reverse proxy in production)
   ▼
 api  ── Fastify: auth, sessions, mailbox API, key directory, static SPA
   │ SQL (parameterized)                 │ blob API
   ▼                                     ▼
 Postgres  ◄───────────────────────  Blob store (filesystem driver; S3-compatible is a documented extension)
   ▲                                     ▲
   │                                     │
 mx-bridge ── LMTP :2424 (inbound processing, encrypt-on-arrival)
   │          tcp_table :2425 (recipient existence lookup for Postfix)
   ▲
 postfix ──── :25 public MX (no relay), :10025 submission (worker network only)
   ▲                ▲
   │                │ SMTP (plaintext MIME, DKIM-signed by worker)
 Internet        worker ── outbound queue, retries, retention jobs
```

Each box is a separate process (and container in Docker Compose). They share one codebase but not one runtime:

1. **Browser application** – all E2EE operations, HTML sanitization and rendering, local search.
2. **API (`api`)** – authentication, sessions, authorization, mailbox storage of ciphertext, key directory, rate limits. Never receives the login password or Mailbox Key.
3. **Mail transfer (`postfix`)** – an established MTA. VoidMail does not implement SMTP itself; the Node side uses `smtp-server` only as an **LMTP** endpoint behind Postfix and `nodemailer` only as an SMTP client to Postfix.
4. **Inbound processing (`mx-bridge`)** and **outbound delivery (`worker`)**.
5. **Encrypted storage** – Postgres for ciphertext + metadata, blob store for encrypted attachments.
6. **Administration** – `npm run admin` CLI. No web admin panel. No decryption capability. Every action is written to `admin_audit`.

## 3. What VoidMail can read and cannot read

| Data | Internal VoidMail→VoidMail message | External inbound | External outbound |
|---|---|---|---|
| Subject | ❌ E2EE | ✅ at arrival, then encrypted to recipient key | ✅ while sending; stored copy encrypted to sender key |
| Body | ❌ E2EE | ✅ at arrival | ✅ while sending |
| Attachments | ❌ E2EE (server stores ciphertext) | ✅ at arrival | ✅ while sending (browser releases attachment keys to the server for this send only) |
| Sender and recipient addresses | ✅ (envelope; required to route) | ✅ | ✅ |
| BCC recipients | ✅ server routes to them; **not** shown to other recipients | n/a | ✅ envelope only; no `Bcc:` header is emitted |
| Timestamps, sizes, folder, read/star flags, label names | ✅ | ✅ | ✅ |
| Message-ID / In-Reply-To (threading) | ✅ | ✅ | ✅ |
| Drafts | ❌ E2EE (encrypted to own key before autosave) | – | ❌ until you press Send |
| Contact key pins and verification state | ❌ (encrypted + signed vault) | – | – |

**Remote mail servers** receiving external mail see the full content of standard email plus all headers.
**Network operators** see IP addresses, timing and sizes; with opportunistic TLS they may be able to strip TLS and read SMTP traffic.

## 4. Sending modes and their labels

| Mode (UI label) | When | Actual behaviour | Tested by |
|---|---|---|---|
| **End-to-end encrypted** | All recipients are VoidMail users with an available key | Browser encrypts subject, body and attachment keys separately for each recipient and for the sender's Sent copy; server receives ciphertext only. | `tests/integration/mail.test.ts`, e2e |
| **Standard email · TLS when available** | At least one external recipient (default) | Browser sends plaintext over HTTPS; server builds MIME, DKIM-signs, hands to Postfix; Postfix uses TLS if the remote server offers it (`smtp_tls_security_level=may`), otherwise plaintext. Stored Sent copy is encrypted to the sender's key. | `tests/e2e/smtp.e2e.test.ts` |
| **Standard email · Require TLS** | User selects it | Same as above but routed through the `smtp_tlsreq` Postfix transport (`smtp_tls_security_level=verify` in the production overlay; `encrypt` in the dev stack, whose test receiver has a self-signed certificate). If the recipient's server does not support STARTTLS the message is **not** delivered in plaintext; it is deferred and eventually bounced and the user sees the failure. Certificate authentication requires `verify`/DANE (see DEPLOYMENT.md). | `tests/e2e/smtp.e2e.test.ts` |

A message with both internal and external recipients is labelled **Standard email** for everyone, because the server has seen the plaintext.

## 5. Inbound external mail

1. Postfix accepts mail only for configured VoidMail domains (`relay_domains`) and only for existing recipients (`relay_recipient_maps` via the bridge's `tcp_table`). Everything else is rejected at `RCPT TO` (no backscatter, no open relay).
2. Postfix hands the message to `mx-bridge` over LMTP. **Unavoidable exposure:** the message sits in Postfix's queue (plaintext on disk) until LMTP delivery succeeds, normally milliseconds.
3. The bridge parses MIME (mailparser), then immediately encrypts header data, body and each attachment to the recipient's active public key. Only ciphertext is written. The raw message is not stored and not logged.
4. The UI labels these messages **"External · encrypted after arrival"**: the server saw them in plaintext.

## 6. The browser-JavaScript limit (read this)

VoidMail's E2EE runs in JavaScript delivered by VoidMail. A compromised or coerced server can deliver modified code that captures your password or Mailbox Key the next time you unlock. E2EE therefore protects against *database theft, backup theft, passive insiders, storage providers and after-the-fact compromise*, but **not** against an operator or attacker who actively modifies the web application. Mitigations in place: strict CSP, no third-party scripts or CDNs, content-hashed bundle file names, same-origin only. Not in place: independent code verification, reproducible build attestation, a browser extension or native client. This is documented in the UI's security page.

## 7. Authentication

- The password never leaves the browser. The browser derives `master = Argon2id(password, salt, m=64 MiB, t=3, p=1)`, then `authKey = HKDF(master,"voidmail/v1/auth")` and `wrapKey = HKDF(master,"voidmail/v1/wrap")`.
- Only `authKey` is sent. The server stores `Argon2id(authKey)` with a server-side pepper (`AUTH_PEPPER`, the argon2 `secret` parameter).
- Unknown usernames get a deterministic fake salt (HMAC of the username) so the pre-login salt lookup does not reveal account existence.
- Sessions: 256-bit random token in an `HttpOnly; Secure (prod); SameSite=Strict; Path=/` cookie; only its SHA-256 is stored. A new token is issued on every login; a password change or recovery revokes every session and issues a fresh one; enabling 2FA signs out all other sessions. Idle timeout 7 days, absolute 30 days. Listing and revocation in settings.
- CSRF: `SameSite=Strict`, plus per-session CSRF token (HMAC of session id) required in `X-CSRF-Token` on every state-changing request, plus `Origin` check.
- TOTP (RFC 6238, otplib) with 10 single-use recovery codes (stored as SHA-256). TOTP secret encrypted at rest with `TOTP_KEY`.
- Passkeys: **not implemented** (they would not unlock the Mailbox Key without WebAuthn PRF; planned).
- Rate limits: per-IP (in-memory) on login, registration, recovery and sending; per-account progressive login throttling in the database.

## 8. Rendering untrusted email

- HTML is sanitized in the browser with DOMPurify (forbids scripts, event handlers, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<base>`, `<meta>`, `<link>`, SVG/MathML).
- Output is rendered in `<iframe sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" srcdoc=…>`. There is **no `allow-scripts`**, so nothing in the message can execute JavaScript (the dangerous combination is `allow-scripts` + `allow-same-origin`, which is never used). `allow-same-origin` only lets the app measure the content height. The frame document carries its own CSP `default-src 'none'; style-src 'unsafe-inline'; img-src data:` and also inherits the app CSP.
- Trade-off: the app CSP must allow `style-src 'unsafe-inline'` (the srcdoc frame inherits it and email HTML relies on inline styles) and `img-src https:` (so that remote images *can* load after an explicit click). Script execution remains restricted to `'self'`.
- Remote images, CSS `url()` and tracking pixels are blocked by default and counted. Loading them requires an explicit click per message; the iframe CSP is then relaxed to `img-src data: https:` only.
- Links open in a new tab with `rel="noopener noreferrer"`; a warning is shown when visible link text looks like a different URL than the target.
- Attachment filenames are sanitized (path separators, control and bidi-override characters removed) and downloads are forced (`application/octet-stream` blob, never rendered inline).
- No image proxy is implemented (so no SSRF surface); loading remote images reveals your IP address to the sender's server, and the UI says so.
- The server cannot scan E2EE attachments for malware and does not claim to.

## 9. Logging

The API logs method, route pattern, status code and latency only; no bodies, no query strings, no cookies, no IP addresses (see `src/server/logging.ts`). Security events (login success/failure, 2FA changes, session revocation, password/recovery changes) are kept in `security_events` for 30 days with a truncated IP (/24 IPv4, /48 IPv6). Postfix logs contain envelope addresses and remote IPs; see OPERATIONS.md for rotation.

## 10. Administration

- No admin role in the web app. The `admin` CLI can: list users (metadata only), suspend/unsuspend, force session revocation, view queue stats, adjust quotas. It has no command that reads message content, and there is no server-side key capable of decrypting stored mail.
- Each CLI action is recorded in `admin_audit` (actor from `ADMIN_ACTOR` env / OS user, action, target, time) — never message content.
- The operator *can* still modify code (see §6). This is stated, not hidden.

## 11. Internal network trust

- The LMTP listener (:2424) and the recipient-lookup listener (:2425) are **unauthenticated**. They are reachable only on the internal `backend` Compose network (declared `internal: true`, never published). Anyone who can reach them can inject inbound mail or probe which addresses exist, so they must never be exposed.
- Postfix's submission listener (:10025) accepts mail only from the `submission` network (worker only) and only with VoidMail VERP envelope senders; it is not published either. Tested in `tests/e2e/smtp.e2e.test.ts`.
- Postgres is only on the `backend` network. The web API is the only service on the `frontend` network (behind Caddy in production).
