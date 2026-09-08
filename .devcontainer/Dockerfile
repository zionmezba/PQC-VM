# Reproducible build environment for the PQC-VM hybrid-signature experiments.
#
# Pins are deliberate: the manuscript reports liboqs/oqs-provider versions, so
# they must not drift between the authors' run and a reviewer's.
FROM ubuntu:24.04

ARG LIBOQS_TAG=0.16.0
ARG OQSPROVIDER_TAG=0.9.0
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git cmake ninja-build pkg-config \
        ca-certificates curl \
        openssl libssl-dev \
        python3 python3-venv python3-dev \
    && rm -rf /var/lib/apt/lists/*

# --- liboqs (shared, full algorithm set) ---------------------------------
RUN git clone --depth 1 --branch ${LIBOQS_TAG} \
        https://github.com/open-quantum-safe/liboqs.git /src/liboqs \
 && cmake -S /src/liboqs -B /src/liboqs/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD=OFF \
        -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /src/liboqs/build \
 && cmake --install /src/liboqs/build \
 && ldconfig

# --- oqs-provider (needed only for the OpenSSL-CLI comparisons) -----------
RUN git clone --depth 1 --branch ${OQSPROVIDER_TAG} \
        https://github.com/open-quantum-safe/oqs-provider.git /src/oqs-provider \
 && cmake -S /src/oqs-provider -B /src/oqs-provider/build -GNinja \
        -DOPENSSL_ROOT_DIR=/usr \
        -DCMAKE_PREFIX_PATH=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /src/oqs-provider/build \
 && install -Dm755 /src/oqs-provider/build/lib/oqsprovider.so \
        /opt/oqs-modules/oqsprovider.so

# --- Python environment ---------------------------------------------------
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv ${VIRTUAL_ENV}
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# liboqs-python locates liboqs.so via the loader; /usr/local/lib is where
# `cmake --install` put it. Without this it silently tries to build its own.
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV OQS_INSTALL_PATH=/usr/local

# OpenSSL CLI wiring. Two profiles matter to the experiments:
#   - PQC-aware:  OPENSSL_CONF=/work/config/openssl-oqs.cnf  (loads oqsprovider)
#   - legacy:     OPENSSL_CONF unset / default              (no PQC support)
# Nothing is exported by default, so the legacy profile is what you get unless
# a test explicitly opts in. That is intentional: RQ1 depends on it.
ENV OPENSSL_MODULES=/opt/oqs-modules

WORKDIR /work
