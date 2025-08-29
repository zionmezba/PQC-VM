#!/usr/bin/env bash
set -euo pipefail
mkdir -p data
# 10 KB text
base64 /dev/urandom | head -c 10240 > data/payload_10k.bin
# 1 MB binary
base64 /dev/urandom | head -c $((1024*1024)) > data/payload_1m.bin
# 50 MB binary (may take a bit longer)
base64 /dev/urandom | head -c $((50*1024*1024)) > data/payload_50m.bin


echo "Generated data/payload_10k.bin, _1m.bin, _50m.bin"