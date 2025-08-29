#!/usr/bin/env bash
set -euo pipefail
mkdir -p out


# Classical ECDSA P-256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out out/ecdsa.key
openssl req -new -x509 -key out/ecdsa.key -subj "/CN=ECDSA Test/" -out out/ecdsa.crt -days 365


# PQC keys/certs
for ALG in dilithium3 falcon512 sphincs+-sha2-128s-simple; do
case "$ALG" in
sphincs+-sha2-128s-simple) CN=SPHINCS128s ;;
dilithium3) CN=DILITHIUM3 ;;
falcon512) CN=FALCON512 ;;
esac
openssl genpkey -algorithm "$ALG" -out "out/${ALG}.key"
openssl req -new -x509 -key "out/${ALG}.key" -subj "/CN=${CN}/" -out "out/${ALG}.crt" -days 365
done


echo "Keys and self-signed certs generated in ./out"