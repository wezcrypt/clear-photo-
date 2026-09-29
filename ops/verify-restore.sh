#!/usr/bin/env bash
# Proves a backup can be restored: decrypts it, restores into a throw-away Postgres container,
# compares row counts with the manifest, and checks every blob row has its object. Touches no live data.
# Usage: ops/verify-restore.sh backups/voidmail-XXXX.tar.gpg
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
file="${1:?usage: verify-restore.sh <backup.tar.gpg>}"
stage=$(mktemp -d); chmod 700 "$stage"
name="vm-restore-check-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$stage"; }
trap cleanup EXIT
gpg --batch --pinentry-mode loopback --passphrase-fd 3 -d "$file" 3<<<"$BACKUP_PASSPHRASE" | tar -C "$stage" -xf -
image=$(docker compose config --images | grep -m1 postgres)
docker run -d --name "$name" -e POSTGRES_PASSWORD=check -e POSTGRES_USER=check -e POSTGRES_DB=check "$image" >/dev/null
for _ in $(seq 1 60); do docker exec "$name" pg_isready -U check -d check >/dev/null 2>&1 && break; sleep 1; done
sleep 2
docker exec -i "$name" pg_restore -U check -d check --no-owner < "$stage/db.dump"
actual=$(docker exec "$name" psql -U check -d check -At -c \
  "SELECT 'users='||count(*) FROM users UNION ALL SELECT 'messages='||count(*) FROM messages UNION ALL SELECT 'blobs='||count(*) FROM blobs UNION ALL SELECT 'user_keys='||count(*) FROM user_keys")
expected=$(grep -v '^created=' "$stage/manifest.txt")
if [ "$actual" != "$expected" ]; then echo "MISMATCH"; echo "expected:"; echo "$expected"; echo "actual:"; echo "$actual"; exit 1; fi
mkdir "$stage/blobs"; tar -C "$stage/blobs" -xf "$stage/blobs.tar"
missing=0
for key in $(docker exec "$name" psql -U check -d check -At -c "SELECT storage_key FROM blobs"); do
  [ -f "$stage/blobs/${key:0:2}/${key:2:2}/$key" ] || { echo "missing blob $key"; missing=$((missing+1)); }
done
[ "$missing" -eq 0 ] || exit 1
echo "RESTORE VERIFIED: $expected" | tr '\n' ' '; echo
