#!/usr/bin/env bash
set -euo pipefail
mkdir -p data
# 10 KB text
dd if=/dev/urandom bs=1024 count=10 2>/dev/null | base64 > data/payload_10k.bin
# 1 MB binary
dd if=/dev/urandom bs=1024 count=1024 2>/dev/null | base64 > data/payload_1m.bin
# 50 MB binary (may take a bit longer)
dd if=/dev/urandom bs=1024 count=$((50*1024)) 2>/dev/null | base64 > data/payload_50m.bin

echo "Generated data/payload_10k.bin, _1m.bin, _50m.bin"