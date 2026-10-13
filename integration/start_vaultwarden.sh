#!/usr/bin/env bash
# Start a throwaway Vaultwarden on https://127.0.0.1:<port> with a self-signed
# certificate, for integration/vaultwarden_import.py. The Bitwarden CLI only
# talks HTTPS, so it is pointed at the certificate with NODE_EXTRA_CA_CERTS.
#
#   integration/start_vaultwarden.sh <work-dir> [port] [image]
set -euo pipefail

work_dir=${1:?usage: start_vaultwarden.sh <work-dir> [port] [image]}
port=${2:-8443}
image=${3:-vaultwarden/server:1.37.4}

mkdir -p "$work_dir/ssl"
docker rm -f totp-migrator-vaultwarden >/dev/null 2>&1 || true
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -keyout "$work_dir/ssl/key.pem" -out "$work_dir/ssl/cert.pem" 2>/dev/null
# The key only protects a one-day certificate for a throwaway server on
# localhost; the container's user must be able to read it.
chmod 644 "$work_dir/ssl/key.pem"

docker run -d --rm --name totp-migrator-vaultwarden \
  -p "127.0.0.1:${port}:80" \
  -v "$work_dir/ssl:/ssl:ro" \
  -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' \
  -e SIGNUPS_ALLOWED=true \
  -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  "$image" >/dev/null

for _ in $(seq 1 60); do
  if curl -sf --cacert "$work_dir/ssl/cert.pem" "https://127.0.0.1:${port}/alive" >/dev/null; then
    echo "vaultwarden ready on https://127.0.0.1:${port}"
    exit 0
  fi
  sleep 1
done
docker logs totp-migrator-vaultwarden || true
echo "vaultwarden did not start" >&2
exit 1
