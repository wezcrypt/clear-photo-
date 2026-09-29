# Deploying VoidMail

This is a runbook for a **single-server** deployment with Docker Compose. It was written and the configuration
tested locally (see README → Verification). **It has not been deployed to a public server by the author of this
repository**, and no production DNS, certificates or IP reputation have been verified. Treat the first deployment
as a staged rollout (DMARC `p=none`, MTA-STS `mode: testing`, registration closed until you have tested it).

## 1. Prerequisites (outside this repository)

| Requirement | Why | How to check |
|---|---|---|
| A domain you control (e.g. `example.com`) | Addresses `user@example.com` | Registrar access |
| A VPS/server with a **static IPv4** | MX, SPF, PTR must point to a stable address | Provider panel |
| **Outbound TCP port 25 open** | Delivering mail to other providers. Many clouds block it by default (you must request unblocking). | `nc -vz gmail-smtp-in.l.google.com 25` from the server |
| **Inbound TCP 25, 80, 443 open** | MX, ACME HTTP challenge, web app | Provider firewall + `ufw status` |
| **Reverse DNS (PTR)** settable for the IP | Many receivers reject mail from IPs without matching PTR | Provider panel |
| Clean IP reputation | New/recycled IPs are often on blocklists | Check the IP on public DNSBL lookup tools before going live |
| Provider acceptable-use policy allows running a mail server | Some hosts forbid it | Read the provider's terms |
| 2 vCPU / 4 GB RAM / 40 GB disk minimum | Argon2id, Postgres, Postfix, attachments | — |
| Docker Engine ≥ 24 with Compose v2 | Runtime | `docker compose version` |

## 2. DNS

Use `infra/dns/zone-template.txt`. Order of operations:

1. `A` records for `mx.`, `mail.` (web) and `mta-sts.` → server IP. Wait for propagation.
2. Ask the provider to set **PTR** of the IP to `mx.example.com`. `MAIL_HOSTNAME` must be the same name.
3. `MX` → `mx.example.com`.
4. **SPF** `v=spf1 mx -all`.
5. Generate DKIM: `ops/gen-dkim.sh vm1` → publish the printed `vm1._domainkey` TXT record. The private key is written to `secrets/dkim.pem` (mode 600, git-ignored) and mounted into `api` and `worker` as a Compose secret. Messages are signed by the worker's MIME builder (`nodemailer` DKIM, relaxed/relaxed, rsa-sha256).
6. **DMARC** starting at `p=none` with `rua=` reports to a mailbox you read. After ~2 weeks of clean aggregate reports, move to `p=quarantine`, then `p=reject`.
7. **MTA-STS**: edit `infra/caddy/mta-sts.txt` (`mx:` line), publish `_mta-sts` TXT with a new `id=` each time the file changes, start with `mode: testing`, move to `enforce` after TLS reports look clean.
8. **TLS-RPT**: `_smtp._tls` TXT.

Verify with `dig +short MX example.com`, `dig +short TXT vm1._domainkey.example.com`, `dig -x <ip>`.

## 3. Server preparation

```bash
# as root on a fresh Ubuntu/Debian host
apt-get update && apt-get install -y docker.io docker-compose-v2 gnupg ufw
adduser --disabled-password voidmail && usermod -aG docker voidmail
ufw default deny incoming && ufw allow 22/tcp && ufw allow 25/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw enable
# SSH hardening (recommended before anything else): key-only auth, no root password login
#   /etc/ssh/sshd_config: PasswordAuthentication no, PermitRootLogin prohibit-password
systemctl restart ssh
```

## 4. Install

```bash
su - voidmail
git clone <this repository> voidmail && cd voidmail
npm run env:init            # or: sh infra/scripts/gen-env.sh  → .env with random secrets (mode 600)
```

Edit `.env`:

| Variable | Production value |
|---|---|
| `MAIL_DOMAIN` | `example.com` |
| `MAIL_HOSTNAME` | `mx.example.com` (must equal PTR) |
| `WEB_HOST` | `mail.example.com` (add this line) |
| `PUBLIC_ORIGIN` | `https://mail.example.com` |
| `NODE_ENV` | `production` |
| `REGISTRATION_OPEN` | `false` until you have tested; then decide |
| `POSTMASTER_USER` | a username you will register (receives postmaster@/abuse@) |
| `TLSREQ_LEVEL` | `verify` (or `dane` with a DNSSEC-validating resolver) |
| `DKIM_SELECTOR` | `vm1` |

Never commit `.env` or `secrets/`. Back up `.env` **separately** from data backups (it holds `AUTH_PEPPER`; without it no one can log in; with it plus a DB dump, offline password guessing becomes possible).

Then:

```bash
ops/gen-dkim.sh vm1
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
```

Caddy obtains certificates for `WEB_HOST`, `MAIL_HOSTNAME` and `mta-sts.MAIL_DOMAIN` automatically. Postfix reads the MX certificate from Caddy's data volume at start; **restart Postfix after the first certificate issuance and after each renewal** (add a weekly cron: `docker compose ... restart postfix`).

## 5. Post-install checks

1. `https://mail.example.com` loads; response headers include `Content-Security-Policy` and `Strict-Transport-Security`.
2. Register the postmaster account, then set `REGISTRATION_OPEN` as desired and `docker compose ... up -d api`.
3. From an external mailbox, send to `postmaster@example.com`; it should arrive labelled "External · encrypted after arrival".
4. Send from VoidMail to an external mailbox you own. In the received headers check `dkim=pass`, `spf=pass`, `dmarc=pass`, and TLS.
5. Open-relay test from outside: `swaks --server mx.example.com --to someone@gmail.com --from x@y.z` → must be rejected with `554 Relay access denied`.
6. `swaks --server mx.example.com --to nobody@example.com` → `550 No such user`.
7. Confirm port 10025 is **not** reachable from outside (`nc -vz mx.example.com 10025` must fail). It is only published on the internal Compose network.

## 6. Upgrades

```bash
git pull
ops/backup.sh                       # always back up first
docker compose -f docker-compose.yml -f docker-compose.prod.yml build
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d   # 'migrate' runs before api/mx/worker start
```

## 7. Things this repository does NOT do for you

- Request port-25 unblocking, PTR changes, or IP delisting from your provider.
- Monitoring/alerting (see OPERATIONS.md for what to watch).
- Off-site backup storage (ops/backup.sh writes locally; copy the encrypted files elsewhere).
- Spam filtering of inbound mail (no rspamd/SpamAssassin is bundled; see OPERATIONS.md).
- Legal documents (see PRIVACY.md **[LEGAL REVIEW]** items).

## 8. Deployment to the host provided in the request

The request included an SSH target (a root login with a password) for a specific server. From the build environment used to
write this repository, **TCP port 22 on that host was unreachable** (outbound SSH is blocked by the sandbox network
policy), so nothing was deployed and no connection was attempted with the credentials. **Because the root password
was shared in plain text, rotate it and switch to SSH-key authentication before deploying.**

To deploy there yourself, follow §1–§5 on that machine. Before starting, check with the provider that outbound port
25 and PTR configuration are available for that IP.
