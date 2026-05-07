#!/usr/bin/env bash
set -euo pipefail

# Prints SHA-256 hash for RELAY_ADMIN_HASH.
# Usage:
#   ./bin/generate_admin_hash.sh "MyStrongPassword"
#   RELAY_ADMIN_HASH="$(./bin/generate_admin_hash.sh "MyStrongPassword")"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 \"admin password\"" >&2
  exit 1
fi

input="$1"

if command -v shasum >/dev/null 2>&1; then
  printf "%s" "$input" | shasum -a 256 | awk '{print $1}'
  exit 0
fi

if command -v openssl >/dev/null 2>&1; then
  printf "%s" "$input" | openssl dgst -sha256 -binary | xxd -p -c 256
  exit 0
fi

echo "No SHA-256 tool found (need 'shasum' or 'openssl')." >&2
exit 2
