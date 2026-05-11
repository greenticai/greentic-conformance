#!/usr/bin/env bash
# Generates a self-signed cert for the local conformance httpd proxy.
# Idempotent — skips if certs already exist. Intended for CI use only;
# never use these certs against a real suite or RP.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CRT="${DIR}/server.crt"
KEY="${DIR}/server.key"

if [[ -f "$CRT" && -f "$KEY" ]]; then
  echo "[gen-certs] reusing existing $CRT / $KEY"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$KEY" -out "$CRT" \
  -days 1 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName = DNS:localhost'

chmod 644 "$CRT" "$KEY"
echo "[gen-certs] wrote $CRT and $KEY"
