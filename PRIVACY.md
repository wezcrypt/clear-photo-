# VoidMail Privacy Documentation (DRAFT)

> **Status: engineering draft describing implemented behaviour.** It is not a legal privacy policy.
> Items marked **[LEGAL REVIEW]** must be completed by qualified counsel for the operator's jurisdiction
> before any public launch (controller identity, lawful bases, data-subject rights process, retention obligations,
> international transfers, law-enforcement request policy).

## 1. Principles

- Collect only what is needed to operate an email service.
- No phone number. Recovery email is optional.
- No third-party analytics, advertising, tracking SDKs, session replay, remote fonts or CDNs. All assets are served from the VoidMail origin.
- Message content is stored only as ciphertext (see SECURITY_ARCHITECTURE.md for when the server sees plaintext).
- Abuse-prevention telemetry is minimal and separate from product analytics — and there is no product analytics.

## 2. Data inventory

Legend — **Location**: PG = PostgreSQL, BS = blob store, PF = Postfix queue/logs, MEM = process memory, BR = user's browser.
**Access**: who can read it in the clear.

### 2.1 Account (`users`)

| Field | Purpose | Location | Readable by | Retention | Deletion |
|---|---|---|---|---|---|
| `username` | Address local part, login | PG | Operator | Account lifetime | Deleted with account; keyed hash kept in `username_tombstones` to prevent address reuse |
| `display_name` | Shown in From: | PG | Operator | Account lifetime | With account |
| `kdf_salt`, `kdf_params` | Client key derivation | PG | Operator (not secret) | Account lifetime | With account |
| `auth_hash` | Verify login (Argon2id of client-derived key + server pepper) | PG | Nobody can reverse | Account lifetime | With account |
| `mk_wrapped_password`, `mk_wrapped_recovery` | Mailbox Key wrapped by password / recovery key | PG | Only the user (with password or recovery key) | Account lifetime | With account |
| `recovery_auth_hash` | Verify recovery key | PG | Nobody can reverse | Until regenerated | With account |
| `recovery_email` | Optional password-reset link destination | PG | Operator | Until removed by user | User can remove any time; with account |
| `totp_secret_enc` | 2FA | PG (AES-GCM, server key) | Server | While 2FA enabled | Deleted when 2FA disabled |
| `totp_last_step` | TOTP replay prevention | PG | Operator | While 2FA enabled | With account |
| `locale`, `theme`, `remote_images` | Preferences | PG | Operator | Account lifetime | With account |
| `quota_bytes`, `status` | Service limits, suspension | PG | Operator | Account lifetime | With account |
| `failed_logins`, `login_locked_until` | Brute-force throttling | PG | Operator | Reset on success | With account |
| `vault_enc` | Contact key pins (encrypted + signed by user) | PG | Only the user | Account lifetime | With account |
| `created_at` | Operations | PG | Operator | Account lifetime | With account |

### 2.2 Keys (`user_keys`)
Public keys (readable by any logged-in user through the key directory, by design), private keys encrypted with an MK-derived passphrase (readable only by the user), encrypted revocation certificates, status and timestamps. Deleted with the account.

### 2.3 Sessions and security (`sessions`, `login_challenges`, `recovery_codes`, `password_resets`, `security_events`)

| Data | Purpose | Retention |
|---|---|---|
| Session: SHA-256 of token, created/last-seen/expiry, coarse device string ("Firefox on Linux") | Keep you signed in, device list | Until logout/revocation; purged ≤ 7 days idle, 30 days absolute |
| Login challenge (hashed) | 2FA / recovery step | 5–15 minutes |
| 2FA recovery codes (SHA-256) | Account access | Until used/regenerated |
| Password-reset token (hashed) | Email reset | 30 minutes, row purged after 1 day |
| Security events: type, time, **IP prefix only** (/24 IPv4, /48 IPv6) | Show you recent account activity; investigate abuse | **30 days** (configurable `SECURITY_EVENT_RETENTION_DAYS`) |

Full IP addresses are **not** stored in the database. They are used in memory by the rate limiter (per-IP counters, reset every window).

### 2.4 Mail (`messages`, `labels`, `message_labels`, `blobs`, `message_blobs`)

| Data | Location | Readable by server? | Retention |
|---|---|---|---|
| Header ciphertext (subject, from/to/cc, snippet) | PG | No | Until you delete; Trash/Spam auto-purged after 30 days |
| Body ciphertext (text, HTML, attachment keys) | PG | No | Same |
| Attachment ciphertext | BS | No | Until no message references it (shared blobs between internal sender and recipients) |
| Metadata: folder, flags, size, received time, sender address, RFC Message-ID / In-Reply-To, key fingerprint used, security label | PG | **Yes** | Same as message |
| Label names and colours | PG | **Yes** | Until you delete them |
| Inbound dedupe hash (SHA-256 of raw MIME) | PG | Hash only | Same as message |

### 2.5 Sending (`outbound_queue`, `outbound_recipients`, `send_log`)

| Data | Purpose | Retention |
|---|---|---|
| Outbound MIME (AES-GCM, server key) | Hand-off to Postfix | **Deleted as soon as Postfix accepts it** (normally seconds); also deleted on failure/cancel |
| Envelope sender (VERP bounce address), recipient addresses, per-recipient status and diagnostic | Delivery status shown to you; bounce handling | 30 days after completion |
| Send counters (numbers only) | Sending limits | 2 days |

### 2.6 Logs

| Log | Contents | Retention |
|---|---|---|
| API access log (stdout) | Method, route pattern (e.g. `/api/messages/:id`), status, duration. **No IP, no query string, no bodies, no cookies, no user ids.** | Per container log driver — configure rotation (OPERATIONS.md) **[LEGAL REVIEW]** |
| Application errors | Error class and message only; request data is never logged | Same |
| Postfix log (stdout) | Envelope sender/recipient addresses, remote server names/IPs, queue ids, TLS details, delivery status. **No message content.** | Configure ≤ 14 days (OPERATIONS.md) |
| Reverse proxy (production, e.g. Caddy) | By default includes client IP and URL. The provided Caddyfile template **disables access logging**; enable only with a documented reason. | — |
| Infrastructure provider logs (network flow logs, load balancers, DDoS protection) | Outside VoidMail's code; may include IPs | **[LEGAL REVIEW]** — document per provider |

### 2.7 Browser storage
`localStorage` holds only the UI language (`vm-locale`). Keys, passwords, the Mailbox Key and the search index live in memory only and are dropped on reload/tab close. The session cookie is `HttpOnly`, `SameSite=Strict`, `Secure` in production.

## 3. What remote parties see

- **Recipients' mail providers** receive the full content of standard (non-E2EE) email you send, plus headers (From, To, Cc, Subject, Date, Message-ID, DKIM signature). BCC recipients are not listed in headers.
- **Senders' servers** learn your IP address only if you choose to load remote content in a message.
- **Network operators** between mail servers see server IPs, timing and sizes; with opportunistic TLS, possibly content.

## 4. Deletion

- **Message deletion**: moving to Trash, then "Delete forever" (or automatic purge after 30 days) removes the ciphertext rows immediately and attachment objects once unreferenced.
- **Account deletion** (Settings → Delete account, requires password): deletes the account row and — by cascade — keys, sessions, messages, labels, codes, security events and send counters; cancels queued outbound mail and deletes its payload; deletes attachment objects not referenced by other users' messages (an internal recipient keeps their own copy of what you sent them).
- **Limits of deletion**:
  - **Backups**: encrypted backups taken before deletion still contain the data until they expire under the backup rotation (default recommendation: 14 daily + 4 weekly, i.e. ≤ 35 days). Restoring a backup after an account deletion requires re-applying deletions (OPERATIONS.md §Backups). Deletion is **not** instantaneous across backups.
  - **Postfix queue**: mail already handed to Postfix may remain in its queue until delivered or bounced (≤ 5 days).
  - **Recipients**: copies delivered to other people — inside or outside VoidMail — are not deleted.
  - **Logs**: Postfix logs referencing your address expire on log rotation.
  - **Legal holds**: **[LEGAL REVIEW]** — describe any legally required retention and how it interacts with the above.

## 5. Data export
Settings → "Export all mail" decrypts every message **in your browser** and downloads a JSON file with messages, attachments (base64), contact pins and account metadata (`GET /api/export/account`). The server never produces a plaintext export.

## 6. Abuse prevention vs. analytics
VoidMail keeps only: per-IP in-memory rate-limit counters, per-account failed-login counters, send counters, and the security events above. They are used to stop brute-force attacks, spam and compromised-account abuse. There is **no** product analytics, usage tracking or profiling.

## 7. Items requiring legal input
- Controller/operator identity and contact **[LEGAL REVIEW]**
- Lawful bases per processing purpose **[LEGAL REVIEW]**
- Data-subject request handling and timelines **[LEGAL REVIEW]**
- Law-enforcement / government request policy and transparency reporting **[LEGAL REVIEW]**
- Hosting locations and international transfers **[LEGAL REVIEW]**
- Mandatory retention (if any) in the operating jurisdiction **[LEGAL REVIEW]**
