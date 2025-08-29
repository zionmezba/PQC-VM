#!/usr/bin/env bash
# PQC-VM Environment Setup

export OQS_PROVIDER_MODULE=$(pwd)/oqs-provider/build/lib/oqsprovider.so
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules:$(dirname "$OQS_PROVIDER_MODULE")
export OPENSSL_CONF=$(pwd)/openssl-oqs.cnf
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

echo "Environment variables set for PQC-VM:"
echo "OQS_PROVIDER_MODULE=$OQS_PROVIDER_MODULE"
echo "OPENSSL_MODULES=$OPENSSL_MODULES"
echo "OPENSSL_CONF=$OPENSSL_CONF"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
