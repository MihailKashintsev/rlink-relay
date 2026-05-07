#!/usr/bin/env bash
set -euo pipefail

# Generates VAPID keys for Web Push (P-256, ES256).
# Prints env vars for relay_server.

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

priv_der="$tmp_dir/vapid_private.der"
pub_der="$tmp_dir/vapid_public.der"
priv_pem="$tmp_dir/vapid_private.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "$priv_pem" >/dev/null 2>&1
openssl ec -in "$priv_pem" -outform DER -out "$priv_der" >/dev/null 2>&1
openssl ec -in "$priv_pem" -pubout -outform DER -out "$pub_der" >/dev/null 2>&1

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

vapid_public_key="$(tail -c 65 "$pub_der" | b64url)"

echo "VAPID_SUBJECT=mailto:admin@your-domain.com"
echo "VAPID_PUBLIC_KEY=$vapid_public_key"
echo "VAPID_PRIVATE_KEY_PEM<<'EOF'"
cat "$priv_pem"
echo "EOF"
