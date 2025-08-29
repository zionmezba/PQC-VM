#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install -y build-essential git cmake ninja-build pkg-config \
                        wget curl unzip ca-certificates python3-pip \
                        openssl libssl-dev
# Get Open Quantum Safe provider (prebuilt via apt is not typical)
# Build oqs-provider + liboqs from source (simple, ~5–10 min)
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=OFF
cmake --build liboqs/build --config Release
sudo cmake --install liboqs/build

git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cmake -S oqs-provider -B oqs-provider/build -GNinja -DOPENSSL_ROOT_DIR=/usr -DCMAKE_PREFIX_PATH=/usr/local
cmake --build oqs-provider/build --config Release
# Register provider path
echo 'export OQS_PROVIDER_MODULE=$(pwd)/oqs-provider/build/lib/oqsprovider.so' >> ~/.bashrc
echo 'export OPENSSL_MODULES=$(dirname "$OQS_PROVIDER_MODULE")' >> ~/.bashrc
echo 'export OPENSSL_CONF=$(pwd)/openssl-oqs.cnf' >> ~/.bashrc

cat > openssl-oqs.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect
[default_sect]
activate = 1
[oqsprovider_sect]
module = $ENV::OQS_PROVIDER_MODULE
activate = 1
[algorithm_sect]
default_properties = fips=no
EOF
