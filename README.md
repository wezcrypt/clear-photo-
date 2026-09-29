# VoidMail

Private email with honest security guarantees, minimal data collection and clear user control.

> **Status: working, locally tested prototype. Not production-ready and not independently audited.**
> Read [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) before trusting it with anything, and
> [Unresolved risks and production blockers](#unresolved-risks-and-production-blockers) below.

| Document | Contents |
|---|---|
| [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) | Components, what the server can and cannot read, sending modes, rendering, logging |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Assets, trust boundaries, adversaries, assumptions, non-goals |
| [ENCRYPTION.md](ENCRYPTION.md) | Key hierarchy, key lifecycle, message formats, key verification, recovery |
| [PRIVACY.md](PRIVACY.md) | Data inventory, retention, deletion limits (draft, needs legal review) |
| [DEPLOYMENT.md](DEPLOYMENT.md) | DNS (MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT/PTR), install, post-install checks |
| [OPERATIONS.md](OPERATIONS.md) | Admin CLI, queues, bounces, abuse response, retention, backups, secret rotation |

## What it is

- **Webmail** (React, English + Arabic with full RTL, dark/light themes, keyboard navigation, mobile layout; locally hosted fonts, no third-party requests).
- **End-to-end encryption between VoidMail users** with OpenPGP.js (RFC 9580, AEAD): subjects, bodies, attachments and drafts are encrypted in the browser; the server stores ciphertext.
- **Standard email with other providers**, honestly labelled: inbound mail is encrypted to your key on arrival (the server saw it); outbound mail is readable by the server while sending; "Require TLS" mode refuses plaintext delivery.
- **An established MTA** (Postfix) for SMTP. Node only speaks LMTP behind Postfix and SMTP to Postfix.
- Argon2id everywhere passwords are involved; the password never leaves the browser.
- Recovery key (keeps mail readable) vs. email reset (regains the account, loses old mail), with explicit warnings.
- TOTP 2FA + recovery codes, session/device management, CSRF defences, rate limits, strict CSP, sanitized and sandboxed HTML email with remote content blocked by default.
- Local-only search, client-side export, account deletion, retention jobs, encrypted backups with restore verification.

### Stack choice (brief)

| Layer | Choice | Why |
|---|---|---|
| Web + API | TypeScript, React 19 + Vite, Fastify 5 | One language across client/server; the *same* crypto/protocol module (`src/shared`) runs in the browser and in tests |
| Crypto | OpenPGP.js 6, WebCrypto, hash-wasm (Argon2id), node-argon2 | Maintained, standard protocols; no custom crypto |
| DB | PostgreSQL 16 (parameterized SQL via `pg`), SQL migrations | Relational metadata, `SKIP LOCKED` queue — no Redis needed |
| Blobs | Filesystem driver behind a `BlobStore` interface (ciphertext only) | Simplest reliable option on one server; an S3 driver fits the same interface (not implemented) |
| MTA | Postfix (Ubuntu 24.04 package) | Mature; handles queueing, retries, TLS policy, DSNs |
| MIME | nodemailer (build + DKIM), mailparser (parse), smtp-server (LMTP only) | Maintained, standards-compliant |
| Dev "outside world" | Mailpit ×2 (one plaintext, one STARTTLS-only) | Real SMTP receivers, nothing leaves the machine |

## Quick start (local)

Requirements: Docker with Compose v2, Node 22 (only for running tests from the host).

```bash
npm ci
npm run env:init                 # writes .env with random secrets (never commit it)
docker compose up -d --build     # db, migrate, api, mx, worker, postfix, mailpit, mailpit-tls
open http://localhost:8080       # VoidMail
open http://localhost:8025       # Mailpit: mail "sent to the internet" lands here
```

- Register two accounts in two browser profiles and write to each other → labelled *End-to-end encrypted*.
- Send to anything `@plain.example` → arrives in Mailpit (:8025). `@tls.example` → Mailpit-TLS (:8026, STARTTLS required).
- Simulate an external sender: `swaks --server localhost:2525 --to you@voidmail.test` (or any SMTP client to port 2525).

If Docker Hub rate-limits you, the Dockerfiles accept mirrors with the same digests:
`NODE_IMAGE=mirror.gcr.io/library/node:22-bookworm-slim@sha256:43ac… POSTFIX_BASE_IMAGE=mirror.gcr.io/library/ubuntu:24.04@sha256:0081… docker compose build`.
Behind a TLS-intercepting proxy also set `BUILD_CA_FILE=/path/to/ca.pem BUILD_HTTPS_PROXY=http://proxy:port`.

Development without Docker for the app: run Postgres, set `DATABASE_URL` and the secrets, then `npm run dev:api`, `npm run dev:mx`, `npm run dev:worker`, `npm run dev:web`.

## Tests

```bash
# unit + integration (needs a disposable Postgres; the test suite DROPS the public schema)
docker run -d --name vm-testdb -e POSTGRES_PASSWORD=testpw -e POSTGRES_USER=voidmail -e POSTGRES_DB=voidmail_test -p 127.0.0.1:55432:5432 postgres:16.4-alpine
npm test

# full-stack SMTP tests against the running compose stack
npm run test:e2e

# browser tests (Playwright/Chromium), writes screenshots to docs/screenshots/
npm run test:ui
```

### Verification results (this repository, local run)

| Suite | Result | Covers |
|---|---|---|
| Unit (`tests/unit`, 4 files) | **21 passed** | KDF & downgrade rejection, AES-GCM wrapping (tamper/wrong key/wrong purpose), OpenPGP sign/verify/wrong key/tamper, attachment encryption, recovery-key encoding, HTML sanitizer (scripts, handlers, remote images, CSS urls, srcset, deceptive links, RTL), address/header-injection validation, filename spoofing, DSN parsing, VERP, IP truncation, backoff, DKIM signing |
| Integration (`tests/integration`, 3 files) | **56 passed** | Password never sent; enumeration-resistant login/prelogin; per-account throttling; CSRF/Origin; security headers; session listing/revocation/logout; token hashing; TOTP + replay + recovery codes; password change keeps mail; recovery-key reset keeps mail; email reset loses mail & token single-use; suspension; **no plaintext in any DB column or blob file** for E2EE mail; signature verification; **BCC privacy** (headers + one PKESK per copy); tamper rejection; header/body swap detection; wrong-key failure; **key-change blocking & acceptance**; stale-key rejection; forged-vault rejection; **account isolation** across messages/attachments/labels/drafts/delivery; plaintext-upload rejection; external labels, queue encryption, Bcc stripping; Require-TLS flag; plaintext refused for E2EE; header injection; recipient/day/minute limits; drafts; flags/folders/restore/labels/pagination; quotas; retention purge + orphan blobs; client-side export; account deletion + tombstone; shared-blob survival; inbound MIME/Unicode/Arabic/attachments; LMTP duplicate suppression; per-recipient LMTP results; spam routing; mailbox-full 552; Postfix recipient lookup; **worker: single delivery, concurrent-claim safety, retry/backoff, permanent failure, crashed-lease recovery**; DSN bounce processing |
| Live SMTP e2e (`tests/e2e/smtp.e2e.test.ts`) | **12 passed** | Two accounts via live API; inbound through Postfix; unknown recipient 550 at RCPT; **not an open relay** (554); submission refused from non-worker networks; spoofed envelope senders refused; outbound delivery with Bcc stripped + success DSN → "delivered"; opportunistic STARTTLS; Require-TLS success; **Require-TLS never falls back to plaintext** and bounces back to the sender; real remote 5xx bounce; reset email through the real queue |
| Browser (`tests/e2e/mailbox.ui.ts`, Playwright/Chromium) | **2 passed** | Registration + recovery key gate; E2EE compose (label, key status, attachment, encrypted autosave) and read (signature badge, download); external HTML with tracker: blocked counter, deceptive-link warning, script not executed, **zero requests to remote hosts**; local search; contact verification; Arabic RTL; light theme; mobile layout without horizontal overflow and working drawer; no console errors; key-change warning dialog → accept → send |
| Backups (manual run of the scripts) | **Passed** | `ops/backup.sh` → `ops/verify-restore.sh` reported RESTORE VERIFIED (row counts + every blob present); tampered archive and wrong passphrase rejected; `ops/restore.sh` restored the live dev stack, which came back healthy |

Screenshots of the tested UI are in [`docs/screenshots/`](docs/screenshots/).

## Feature status

| Area | Status |
|---|---|
| Registration, login, unlock, logout, sessions/devices, revocation | Implemented, tested |
| Argon2id (client KDF + server verifier with pepper) | Implemented, tested |
| TOTP 2FA + recovery codes (replay-protected) | Implemented, tested |
| Passkeys / WebAuthn | **Not implemented** (would not unlock E2EE keys without WebAuthn PRF) |
| CSRF, Origin checks, strict CSP, security headers | Implemented, tested |
| Rate limits (per-IP in-memory; per-account DB) | Implemented, tested. In-memory limits are per process (see risks) |
| E2EE internal mail, attachments, drafts, signatures | Implemented, tested |
| Multi-device (password unlock on any device) | Implemented, tested |
| Key rotation, retired-key decryption, key-change warnings, TOFU pins, manual verification | Implemented, tested |
| Recovery key flow / email reset flow with data-loss confirmation | Implemented, tested |
| External inbound (Postfix → LMTP → encrypt on arrival) | Implemented, tested |
| External outbound (opportunistic TLS, Require TLS), DKIM, VERP bounces, DSN status | Implemented, tested (DKIM signing unit-tested; not verified against real receivers) |
| Open-relay prevention, recipient verification, submission restrictions | Implemented, tested |
| SPF/DKIM/DMARC **verification of inbound** mail | **Not implemented** (no authentication results shown; phishing risk) |
| Inbound spam filtering | Partial: honours upstream `X-Spam-Flag`; no bundled filter |
| OpenPGP to external recipients / password-protected external portal | **Not implemented** |
| HTML sanitization, sandboxed rendering, remote-content blocking, deceptive-link warning | Implemented, tested |
| Image proxy | Not implemented (deliberately — no SSRF surface; loading remote images exposes the reader's IP, and the UI says so) |
| Folders, flags, labels, pagination, quotas, reply/reply-all/forward | Implemented; reply/forward UI exercised manually, not by automated UI test |
| Local search (in-memory, explicit "index all") | Implemented, UI-tested |
| Export (client-side decrypted JSON), account deletion | Implemented, tested |
| Retention jobs, admin CLI with audit log | Implemented; retention tested, CLI not covered by automated tests |
| Encrypted backups + verified restore | Implemented, tested locally |
| S3-compatible blob storage | Interface only; **not implemented** |
| Deployment to a public server | **Not done** (see DEPLOYMENT.md §8) |

## Unresolved risks and production blockers

1. **Browser-delivered crypto**: a compromised/coerced server can serve JavaScript that steals passwords/keys. No code-verification mechanism exists.
2. **Key directory trust**: first contact relies on TOFU unless users verify fingerprints out-of-band; vault rollback by the server is possible (no version anchoring).
3. **No inbound SPF/DKIM/DMARC evaluation or spam filter** — spoofed external senders are displayed as claimed. Must be added (e.g. rspamd milter) before public use.
4. **Metadata is visible to the operator** (addresses, timing, sizes, folders, label names).
5. **In-memory per-IP rate limiting** resets on restart and is per process; a shared store is needed for multiple API instances. Per-account throttling can be abused to lock out a victim temporarily (max 60 min).
6. **Outbound hand-off is at-least-once**: a worker crash between Postfix acceptance and the DB update can duplicate one message.
7. **Postfix spool holds plaintext** of external mail transiently (inbound until LMTP succeeds; outbound until remote delivery, up to 5 days for deferred mail). Encrypt the disk.
8. **No independent security audit**, no fuzzing of MIME parsing, no load testing.
9. **Operational prerequisites not verifiable here**: outbound port 25, PTR, IP reputation, real DKIM/DMARC alignment at major receivers, MTA-STS enforcement, certificate renewal hook for Postfix.
10. **Legal**: privacy policy, terms, abuse and law-enforcement processes need counsel ([LEGAL REVIEW] items in PRIVACY.md).
11. **No passkeys, no breached-password check, no password-strength estimation.**
12. **Account-level rotation of `AUTH_PEPPER` is not supported** (all logins would fail).
13. **Base image `ubuntu:24.04` for Postfix** installs the distro Postfix at build time; rebuild regularly for security updates.

## Repository layout

```
src/shared/     crypto.ts (primitives), client.ts (full client protocol), mail.ts (formats/validation)
src/server/     app.ts, routes/, inbound.ts (LMTP processing), outbound.ts (MIME/DKIM/queue), worker.ts,
                lookup.ts (Postfix tcp_table), retention.ts, main.ts (api|mx|worker|migrate|retention|admin), migrations/
src/web/        React app (pages/, components/, lib/sanitize.ts, lib/i18n.ts)
infra/postfix/  MTA image + config templates     infra/caddy/  production reverse proxy + MTA-STS
infra/dns/      zone template                     ops/          backup, restore, verify-restore, DKIM keygen
tests/          unit/, integration/ (in-process), e2e/ (live stack: SMTP + Playwright)
```
