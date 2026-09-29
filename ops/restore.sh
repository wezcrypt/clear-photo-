#!/usr/bin/env bash
# Restores an encrypted backup INTO THE RUNNING COMPOSE STACK (destructive: replaces current data).
# Usage: ops/restore.sh backups/voidmail-XXXX.tar.gpg --yes
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
file="${1:?usage: restore.sh <backup.tar.gpg> --yes}"
[ "${2:-}" = "--yes" ] || { echo "refusing without --yes (this replaces all current data)"; exit 1; }
stage=$(mktemp -d); chmod 700 "$stage"; trap 'rm -rf "$stage"' EXIT
gpg --batch --pinentry-mode loopback --passphrase-fd 3 -d "$file" 3<<<"$BACKUP_PASSPHRASE" | tar -C "$stage" -xf -
docker compose stop api mx worker
docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner < "$stage/db.dump"
docker compose run --rm --no-deps -T --entrypoint sh api -c 'find /data/blobs -mindepth 1 -delete; tar -C /data/blobs -xf -' < "$stage/blobs.tar"
docker compose start api mx worker
cat "$stage/manifest.txt"
