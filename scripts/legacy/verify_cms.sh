#!/usr/bin/env bash
set -euo pipefail
SIG=${1:?Usage: verify_cms.sh <sigfile> [content]}
CONTENT=${2:-data/msg.txt}

# Check the signature file type and verify accordingly
if [[ "$SIG" == *.p7s ]]; then
  # Try CMS verification
  openssl cms -verify -inform DER -in "$SIG" -content "$CONTENT" -purpose any > /dev/null
elif [[ "$SIG" == *.sig ]]; then
  # Basic signature verification - extract public key from corresponding certificate
  ALG=$(basename "$SIG" .sig | sed 's/.*\.//')
  CERT="out/${ALG}.crt"
  if [ -f "$CERT" ]; then
    # Extract public key and verify
    openssl x509 -pubkey -noout -in "$CERT" | openssl dgst -sha256 -verify /dev/stdin -signature "$SIG" "$CONTENT"
  else
    echo "Certificate not found: $CERT" >&2
    exit 1
  fi
elif [[ "$SIG" == *.hybrid ]]; then
  # Hybrid signature verification
  echo "Hybrid signature verification not implemented yet" >&2
  exit 1
else
  echo "Unknown signature format: $SIG" >&2
  exit 1
fi