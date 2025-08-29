#!/usr/bin/env bash
set -euo pipefail
IN=${1:-data/msg.txt}
MODE=${2:-hybrid}
ALG=${3:-mldsa65}
mkdir -p out

case "$MODE" in
  classical)
    OUT=out/$(basename "$IN").ecdsa.p7s
    openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
      -signer out/ecdsa.crt -inkey out/ecdsa.key
    echo "$OUT" ;;
  pqc)
    OUT=out/$(basename "$IN").${ALG}.p7s
    # Try CMS first, fall back to basic signing if it fails
    if ! openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
      -signer "out/${ALG}.crt" -inkey "out/${ALG}.key" -md sha256 2>/dev/null || [ ! -s "$OUT" ]; then
      # CMS failed, use basic signing
      OUT=out/$(basename "$IN").${ALG}.sig
      openssl dgst -sha256 -sign "out/${ALG}.key" -out "$OUT" "$IN"
    fi
    echo "$OUT" ;;
  hybrid)
    OUT=out/$(basename "$IN").ecdsa+${ALG}.p7s
    # Try CMS first
    if ! openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
      -signer out/ecdsa.crt -inkey out/ecdsa.key \
      -signer "out/${ALG}.crt" -inkey "out/${ALG}.key" -md sha256 2>/dev/null || [ ! -s "$OUT" ]; then
      # CMS failed, create hybrid signature manually
      OUT_BASE=out/$(basename "$IN").ecdsa+${ALG}
      OUT="${OUT_BASE}.hybrid"
      
      # ECDSA CMS signature  
      openssl cms -sign -binary -in "$IN" -out "${OUT_BASE}.ecdsa.p7s" -outform DER \
        -signer out/ecdsa.crt -inkey out/ecdsa.key
      
      # PQC basic signature
      openssl dgst -sha256 -sign "out/${ALG}.key" -out "${OUT_BASE}.${ALG}.sig" "$IN"
      
      # Create a simple combined format
      printf "HYBRID:" > "$OUT"
      cat "${OUT_BASE}.ecdsa.p7s" >> "$OUT"
      printf "PQC:" >> "$OUT"
      cat "${OUT_BASE}.${ALG}.sig" >> "$OUT"
    fi
    echo "$OUT" ;;
  *) echo "Unknown MODE: $MODE" >&2; exit 1 ;;
esac