# VoidMail MTA: stock Ubuntu Postfix, configured at start by entrypoint.sh from environment variables.
# Digest-pinned. BASE_IMAGE may point at a registry mirror carrying the same digest.
ARG BASE_IMAGE=ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3
FROM ${BASE_IMAGE}
ARG HTTPS_PROXY
# The optional "buildca" secret exists only for build environments behind a TLS-intercepting proxy.
RUN --mount=type=secret,id=buildca,required=false \
    set -e; \
    if [ -s /run/secrets/buildca ]; then \
      cp /run/secrets/buildca /tmp/buildca.crt && chmod 644 /tmp/buildca.crt; \
      printf 'Acquire::https::Proxy "%s";\nAcquire::https::CAInfo "/tmp/buildca.crt";\n' "$HTTPS_PROXY" > /etc/apt/apt.conf.d/99build; \
      sed -i 's|http://|https://|g' /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix postfix-pcre ca-certificates openssl netcat-openbsd; \
    rm -f /etc/apt/apt.conf.d/99build /tmp/buildca.crt; \
    rm -rf /var/lib/apt/lists/*
COPY main.cf.tmpl master.cf.append submission_header_checks.pcre submission_sender_access.pcre /etc/postfix/voidmail/
COPY entrypoint.sh gen-dev-certs.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/gen-dev-certs.sh
EXPOSE 25 10025
HEALTHCHECK --interval=15s --timeout=5s --retries=6 CMD nc -z 127.0.0.1 25 && nc -z 127.0.0.1 10025 || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
