#!/bin/sh
# Self-signed certificates for LOCAL DEVELOPMENT ONLY.
set -eu
out="${1:-/certs}"
mkdir -p "$out"
for name in mx mailpit-tls; do
  if [ ! -f "$out/$name.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$name" \
      -keyout "$out/$name.key" -out "$out/$name.pem" >/dev/null 2>&1
  fi
done
chmod 644 "$out"/*.pem "$out"/*.key
echo "dev certificates in $out"
