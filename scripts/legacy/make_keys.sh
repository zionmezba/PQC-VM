#!/usr/bin/env bash
set -euo pipefail
mkdir -p out

# Classical ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out out/ecdsa.key
openssl req -new -x509 -key out/ecdsa.key -subj "/CN=ECDSA Test/" -out out/ecdsa.crt -days 365

# PQC keys/certs
for ALG in mldsa65 falcon512 sphincssha2128ssimple; do
  case "$ALG" in
    sphincssha2128ssimple) CN=SPHINCS128s ;;
    mldsa65) CN=MLDSA65 ;;
    falcon512) CN=FALCON512 ;;
  esac
  openssl genpkey -algorithm "$ALG" -out "out/${ALG}.key"
  openssl req -new -x509 -key "out/${ALG}.key" -subj "/CN=${CN}/" -out "out/${ALG}.crt" -days 365
done

echo "Keys and self-signed certs generated in ./out"