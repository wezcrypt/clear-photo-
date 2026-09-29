#!/usr/bin/env bash
# Encrypted backup of the database and the encrypted-attachment blob store.
# Usage: ops/backup.sh [output-dir]      (reads BACKUP_PASSPHRASE, POSTGRES_* from .env)
# The archive is encrypted with GnuPG symmetric AES-256 before it touches the output directory.
# Plaintext staging happens in a private temp dir (mode 0700) that is removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
: "${BACKUP_PASSPHRASE:?BACKUP_PASSPHRASE must be set in .env}"
out="${1:-./backups}"
mkdir -p "$out"
stage=$(mktemp -d)
chmod 700 "$stage"
trap 'rm -rf "$stage"' EXIT

ts=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec -T db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner > "$stage/db.dump"
docker compose exec -T api tar -C /data/blobs -cf - . > "$stage/blobs.tar"
# Manifest used by ops/verify-restore.sh to prove the restore is complete.
docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -c \
  "SELECT 'users='||count(*) FROM users UNION ALL SELECT 'messages='||count(*) FROM messages UNION ALL SELECT 'blobs='||count(*) FROM blobs UNION ALL SELECT 'user_keys='||count(*) FROM user_keys" > "$stage/manifest.txt"
echo "created=$ts" >> "$stage/manifest.txt"

tar -C "$stage" -cf - db.dump blobs.tar manifest.txt | \
  gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --symmetric \
      --cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 --compress-algo none \
      -o "$out/voidmail-$ts.tar.gpg" 3<<<"$BACKUP_PASSPHRASE"
chmod 600 "$out/voidmail-$ts.tar.gpg"
echo "$out/voidmail-$ts.tar.gpg"
