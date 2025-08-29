#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y build-essential git cmake ninja-build pkg-config \
                        wget curl unzip ca-certificates python3-pip \
                        openssl libssl-dev default-jre default-jdk

# Build and install liboqs
if [ ! -d liboqs ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
fi
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=OFF
cmake --build liboqs/build --config Release
sudo cmake --install liboqs/build

# Build and place oqs-provider
if [ ! -d oqs-provider ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
fi
cmake -S oqs-provider -B oqs-provider/build -GNinja -DOPENSSL_ROOT_DIR=/usr -DCMAKE_PREFIX_PATH=/usr/local
cmake --build oqs-provider/build --config Release

# Environment wiring
cat > /workspaces/openssl-oqs.env <<'ENV'
export OQS_PROVIDER_MODULE=/workspaces/pqc-hybrid-lab/oqs-provider/build/lib/oqsprovider.so
export OPENSSL_MODULES=$(dirname "$OQS_PROVIDER_MODULE")
export OPENSSL_CONF=/workspaces/pqc-hybrid-lab/config/openssl-oqs.cnf
ENV

# Persist to shell
if ! grep -q openssl-oqs.env ~/.bashrc; then
  echo 'source /workspaces/openssl-oqs.env' >> ~/.bashrc
fi

mkdir -p out results data scripts config
[ -f data/msg.txt ] || echo "hello pqc world" > data/msg.txt

# Verify presence (non-fatal)
source /workspaces/openssl-oqs.env || true
openssl list -signature-algorithms | grep -i -E "dilithium|falcon|sphincs" || true