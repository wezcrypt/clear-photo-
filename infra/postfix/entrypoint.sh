#!/bin/sh
set -eu
: "${MAIL_DOMAIN:?MAIL_DOMAIN is required}"
: "${MAIL_HOSTNAME:=mx.$MAIL_DOMAIN}"
: "${SUBMISSION_NETWORK:?SUBMISSION_NETWORK (CIDR of the worker network) is required}"
: "${MX_BRIDGE_HOST:=mx}"
: "${DEFAULT_TRANSPORT:=smtp}"
: "${TLSREQ_TRANSPORT:=smtp_tlsreq:}"
: "${TLSREQ_LEVEL:=encrypt}"
: "${EXTRA_TRANSPORTS:=}"
export MAIL_DOMAIN MAIL_HOSTNAME SUBMISSION_NETWORK MX_BRIDGE_HOST DEFAULT_TRANSPORT TLSREQ_TRANSPORT TLSREQ_LEVEL EXTRA_TRANSPORTS

render() { # minimal ${VAR} substitution without envsubst
  awk '{ while (match($0, /\$\{[A-Z_]+\}/)) { v = substr($0, RSTART+2, RLENGTH-3); $0 = substr($0, 1, RSTART-1) ENVIRON[v] substr($0, RSTART+RLENGTH) } print }' "$1"
}

render /etc/postfix/voidmail/main.cf.tmpl > /etc/postfix/main.cf
cp /usr/share/postfix/master.cf.dist /etc/postfix/master.cf 2>/dev/null || true
render /etc/postfix/voidmail/master.cf.append >> /etc/postfix/master.cf
# Run every service unchrooted (container already isolates; avoids copying resolv.conf into the chroot).
postconf -F '*/*/chroot = n'

cp /etc/postfix/voidmail/submission_header_checks.pcre /etc/postfix/
dom_re=$(printf '%s' "$MAIL_DOMAIN" | sed 's/\./\\./g')
{ cat /etc/postfix/voidmail/submission_sender_access.pcre
  printf '/^bounces\\+[0-9a-f]{32}(\\.tls)?@%s$/ OK\n' "$dom_re"
  printf '/^no-reply@%s$/ REJECT\n' "$dom_re"
} > /etc/postfix/submission_sender_access.pcre
printf '/^bounces\\+[0-9a-f]{32}\\.tls@%s$/ %s\n' "$dom_re" "$TLSREQ_TRANSPORT" > /etc/postfix/sender_transport.pcre

mkdir -p /etc/postfix/tls
if [ -n "${TLS_CERT_FILE:-}" ] && [ -f "$TLS_CERT_FILE" ]; then
  cp "$TLS_CERT_FILE" /etc/postfix/tls/cert.pem; cp "$TLS_KEY_FILE" /etc/postfix/tls/key.pem
elif [ ! -f /etc/postfix/tls/cert.pem ]; then
  echo "[postfix] WARNING: no TLS_CERT_FILE given, generating a self-signed certificate (development only)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$MAIL_HOSTNAME" \
    -keyout /etc/postfix/tls/key.pem -out /etc/postfix/tls/cert.pem >/dev/null 2>&1
fi
chmod 600 /etc/postfix/tls/key.pem

# Service mail (password-reset links) is submitted with a bounces+ envelope, so no-reply is never a valid sender.
cp /etc/resolv.conf /var/spool/postfix/etc/resolv.conf 2>/dev/null || true
postfix check
exec postfix start-fg
