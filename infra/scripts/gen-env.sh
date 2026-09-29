#!/bin/sh
# Creates .env with freshly generated random secrets for LOCAL DEVELOPMENT. Never commit .env.
set -eu
[ -f .env ] && { echo ".env already exists; refusing to overwrite"; exit 1; }
hex() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
sed -e "s/^APP_SECRET=.*/APP_SECRET=$(hex)/" \
    -e "s/^AUTH_PEPPER=.*/AUTH_PEPPER=$(hex)/" \
    -e "s/^QUEUE_KEY=.*/QUEUE_KEY=$(hex)/" \
    -e "s/^TOTP_KEY=.*/TOTP_KEY=$(hex)/" \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(hex | cut -c1-32)/" \
    -e "s/^BACKUP_PASSPHRASE=.*/BACKUP_PASSPHRASE=$(hex)/" \
    .env.example > .env
chmod 600 .env
echo "wrote .env with random secrets"
