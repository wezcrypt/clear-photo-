#!/usr/bin/env bash
# Generates a 2048-bit RSA DKIM key into ./secrets/dkim.pem and prints the DNS TXT record.
set -euo pipefail
cd "$(dirname "$0")/.."
selector="${1:-vm1}"
mkdir -p secrets && chmod 700 secrets
[ -f secrets/dkim.pem ] && { echo "secrets/dkim.pem exists; refusing to overwrite"; exit 1; }
openssl genrsa -out secrets/dkim.pem 2048 2>/dev/null
chmod 600 secrets/dkim.pem
pub=$(openssl rsa -in secrets/dkim.pem -pubout -outform der 2>/dev/null | openssl base64 -A)
echo "Add this TXT record:"
echo "${selector}._domainkey.<your-domain>  TXT  \"v=DKIM1; k=rsa; p=${pub}\""
