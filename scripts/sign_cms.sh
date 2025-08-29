#!/usr/bin/env bash
set -euo pipefail
IN=${1:-data/msg.txt}
MODE=${2:-hybrid}
ALG=${3:-dilithium3}
mkdir -p out


case "$MODE" in
classical)
OUT=out/$(basename "$IN").ecdsa.p7s
openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
-signer out/ecdsa.crt -inkey out/ecdsa.key
echo "$OUT" ;;
pqc)
OUT=out/$(basename "$IN").${ALG}.p7s
openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
-signer "out/${ALG}.crt" -inkey "out/${ALG}.key"
echo "$OUT" ;;
hybrid)
OUT=out/$(basename "$IN").ecdsa+${ALG}.p7s
openssl cms -sign -binary -in "$IN" -out "$OUT" -outform DER \
-signer out/ecdsa.crt -inkey out/ecdsa.key \
-signer "out/${ALG}.crt" -inkey "out/${ALG}.key"
echo "$OUT" ;;
*) echo "Unknown MODE: $MODE" >&2; exit 1 ;;
esac