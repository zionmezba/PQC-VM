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
    OUT=out/$(basename "$IN").${ALG}.sig
    # Use basic signing since CMS doesn't work with these PQC algorithms
    openssl dgst -sha256 -sign "out/${ALG}.key" -out "$OUT" "$IN"
    echo "$OUT" ;;
  hybrid)
    # Create separate signatures for hybrid approach
    OUT_BASE=out/$(basename "$IN").ecdsa+${ALG}
    OUT_ECDSA="${OUT_BASE}.ecdsa.sig"
    OUT_PQC="${OUT_BASE}.${ALG}.sig"
    OUT="${OUT_BASE}.hybrid.sig"
    
    # ECDSA signature  
    openssl cms -sign -binary -in "$IN" -out "$OUT_ECDSA" -outform DER \
      -signer out/ecdsa.crt -inkey out/ecdsa.key
    
    # PQC signature
    openssl dgst -sha256 -sign "out/${ALG}.key" -out "$OUT_PQC" "$IN"
    
    # Combine them in a simple format
    {
      echo "HYBRID_SIGNATURE_V1"
      echo "ECDSA_SIZE=$(stat -c%s "$OUT_ECDSA")"
      echo "PQC_SIZE=$(stat -c%s "$OUT_PQC")"
      echo "ECDSA_DATA:"
      cat "$OUT_ECDSA"
      echo "PQC_DATA:"
      cat "$OUT_PQC"
    } > "$OUT"
    
    echo "$OUT" ;;
  *) echo "Unknown MODE: $MODE" >&2; exit 1 ;;
esac
