# VoidMail Operations Runbook

All commands assume the repository root on the server and
`alias dc='docker compose -f docker-compose.yml -f docker-compose.prod.yml'` (development: plain `docker compose`).

## 1. Services

| Service | Role | Health |
|---|---|---|
| `db` | PostgreSQL 16 | `pg_isready` healthcheck |
| `migrate` | One-shot schema migrations before app start | exits 0 |
| `api` | Web app + JSON API (port 8080 on the internal network) | `GET /api/health` |
| `mx` | LMTP bridge :2424 (encrypt-on-arrival) + Postfix recipient lookup :2425 | TCP healthcheck |
| `worker` | Outbound queue → Postfix; hourly retention jobs | logs `[worker]` |
| `postfix` | MTA: public :25, internal submission :10025 | TCP healthcheck |
| `caddy` (prod) | TLS termination, ACME, MTA-STS policy | — |

## 2. Administration (no content access)

```bash
dc exec api node dist/server/main.js admin                     # help
dc exec -e ADMIN_ACTOR=alice-ops api node dist/server/main.js admin users
dc exec -e ADMIN_ACTOR=alice-ops api node dist/server/main.js admin suspend <username>
dc exec -e ADMIN_ACTOR=alice-ops api node dist/server/main.js admin revoke-sessions <username>
dc exec -e ADMIN_ACTOR=alice-ops api node dist/server/main.js admin set-quota <username> <bytes>
dc exec -e ADMIN_ACTOR=alice-ops api node dist/server/main.js admin delete-user <username> --confirm
dc exec api node dist/server/main.js admin queue
dc exec api node dist/server/main.js admin audit              # last 50 admin actions
```

Every command writes `admin_audit(actor, action, target, time)`. There is no command, key or code path that decrypts
stored mail. Always set `ADMIN_ACTOR` to a real person's identifier. Restrict SSH/Docker access to the server — anyone with
Docker access can also modify code (see SECURITY_ARCHITECTURE.md §6), so treat that group as fully trusted and keep it small.

## 3. Mail queue, retries, bounces, loops

- **VoidMail queue** (`outbound_queue`): worker hands mail to Postfix. Retries a failed hand-off with backoff 30 s → 2 m → 5 m → 15 m → 30 m → 1 h → 2 h → 4 h (8 attempts), then marks it failed and notifies the sender. Leases (5 min) make concurrent workers safe; a worker crash inside the send window can cause one duplicate hand-off (at-least-once).
- **Postfix queue**: remote delivery retries for up to `maximal_queue_lifetime = 5d`, delay warnings after 4 h.
  - Inspect: `dc exec postfix postqueue -p` (or `-j` for JSON).
  - Flush: `dc exec postfix postqueue -f`.
  - Delete one message: `dc exec postfix postsuper -d <queue_id>`.
  - Expire (bounce now): `dc exec postfix postsuper -e <queue_id> && dc exec postfix postqueue -i <queue_id>`.
- **Bounces**: every outbound message uses a VERP envelope sender `bounces+<queue-id>[.tls]@domain`. DSNs return to the bridge, update per-recipient status, and put one "Delivery failed" notice in the sender's inbox. DSNs are requested with `RET=HDRS`, so bounces carry headers, not bodies.
- **Loop prevention**: bounces are never answered or forwarded; there is no auto-responder or forwarding feature; Postfix `hopcount_limit = 30`; mail to unknown recipients is rejected at RCPT (no backscatter).
- **Require-TLS mail** goes through the `smtp_tlsreq` transport (`smtp_tls_security_level=verify` in production). If the receiver has no valid TLS, Postfix defers it and eventually bounces — it is never sent in plaintext.

## 4. Sending limits and abuse

Defaults (`.env`): 50 recipients/message, 10 sends/minute, 200 external recipients/day, 2000 internal recipients/day per user, 1 GB quota. There is no bulk-sending feature.

**Compromised or abusive account response**
1. `admin suspend <username>` — revokes all sessions, cancels queued outbound mail and deletes its payload.
2. Check `dc exec postfix postqueue -p` for mail from that account already handed to Postfix (`bounces+<id>`); delete it with `postsuper -d`.
3. Review `security_events` for the account (type/time/IP prefix only) — `dc exec db psql -U voidmail -c "SELECT type, ip_prefix, created_at FROM security_events WHERE user_id=(SELECT id FROM users WHERE username='X') ORDER BY created_at DESC LIMIT 50"`.
4. Contact the owner through the recovery email if set. They should change the password (keeps mail) and review devices.
5. `admin unsuspend` when resolved. Record the incident outside the system.

**Abuse reports** arrive at `abuse@` (routed to `POSTMASTER_USER`). Answer within your published SLA **[LEGAL REVIEW]**.

**Inbound spam**: VoidMail has no bundled content filter. It honours `X-Spam-Flag: YES` / `X-Spam-Status: Yes` added by an upstream filter. Recommended: run rspamd as a Postfix milter (`smtpd_milters`) in front of the bridge; note that the filter then sees inbound plaintext too (document it in PRIVACY.md). DNSBL checks can be added with `postscreen` or `reject_rbl_client` in `smtpd_recipient_restrictions`.

## 5. Retention jobs

The worker runs retention hourly (run it now with `dc exec api node dist/server/main.js retention`):

| Data | Rule |
|---|---|
| Trash / Spam | purged 30 days after being moved there (`TRASH_RETENTION_DAYS`) |
| Sessions | expired or idle > 7 days |
| Login challenges | expired |
| Password-reset tokens | 1 day after expiry |
| Security events | 30 days (`SECURITY_EVENT_RETENTION_DAYS`) |
| Send counters | 2 days |
| Delivery-status rows | 30 days after completion (payload already deleted on hand-off) |
| Orphaned attachment objects | unreferenced for 24 h |

## 6. Logs

- Docker log rotation (put in `/etc/docker/daemon.json`):
  `{"log-driver":"json-file","log-opts":{"max-size":"20m","max-file":"5"}}` — then `systemctl restart docker`.
- API logs contain no IPs or content. Postfix logs contain envelope addresses and remote IPs: keep ≤ 14 days.
- Caddy access logging is disabled in the provided Caddyfile.

## 7. Backups and restore

```bash
ops/backup.sh /var/backups/voidmail          # encrypted .tar.gpg (AES-256, passphrase from BACKUP_PASSPHRASE)
ops/verify-restore.sh /var/backups/voidmail/voidmail-<ts>.tar.gpg   # restores into a scratch DB, checks counts + blobs
ops/restore.sh /var/backups/voidmail/voidmail-<ts>.tar.gpg --yes    # DESTRUCTIVE: replaces live data
```

- Contents: `pg_dump` (custom format), the blob store (already ciphertext), a manifest. Message contents inside are ciphertext either way; the backup encryption protects metadata, account data and verifiers.
- Suggested schedule (cron as the `voidmail` user): daily backup; keep 14 daily + 4 weekly; copy off-site; run `verify-restore.sh` on the newest backup weekly and alert on failure.
- Keep `BACKUP_PASSPHRASE` and `.env` in a separate secret store — not next to the backups.
- **Deletion vs. backups**: accounts deleted after a backup still exist in that backup until it rotates out. After a restore, re-apply deletions recorded since the backup (`admin_audit` rows with `delete_user`, and user-initiated deletions: keep a list of deleted usernames from `username_tombstones` timestamps) before reopening the service.

## 8. Key and secret rotation

| Secret | Rotation impact |
|---|---|
| `QUEUE_KEY` | Only affects in-flight queue rows. Drain the queue (`admin queue` shows 0 queued) before changing. |
| `TOTP_KEY` | Existing TOTP secrets become unreadable → users must re-enroll 2FA. Avoid unless compromised. |
| `AUTH_PEPPER` | All logins fail. Only rotate with a planned re-hash strategy (not implemented). |
| `APP_SECRET` | CSRF tokens and decoy salts change (users re-login); tombstone hashes change → deleted usernames become re-registrable. Avoid. |
| DKIM key | Publish new selector, switch `DKIM_SELECTOR`/key, remove old record after a week. |
| TLS certs | Automatic (Caddy); restart Postfix after renewal. |

## 9. Monitoring checklist (not bundled)

Alert on: API health failing; Postfix queue size > 100 or oldest message > 1 h; `outbound_queue` rows in `failed`; disk > 80 %; backup job failure; certificate expiry < 14 days; DMARC/TLS-RPT reports showing failures; sudden per-user send spikes (`send_log`).
