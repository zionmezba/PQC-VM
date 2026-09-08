#!/usr/bin/env bash
# Generate the on-disk payloads at their nominal sizes.
#
# The previous version piped `dd` through base64, which inflated every file by
# ~4/3 -- "payload_10k.bin" was 13,836 bytes. Sizes here are exact, and are
# asserted before the script exits so a silent short read cannot slip through.
set -euo pipefail

mkdir -p data

# A non-empty base message. A zero-byte data/msg.txt is what caused a third of
# the original runs to sign nothing at all.
printf 'PQC-VM hybrid signature test document.\n' > data/msg.txt

gen() {
  local path="$1" bytes="$2"
  dd if=/dev/urandom of="$path" bs=1024 count=$((bytes / 1024)) \
     status=none iflag=fullblock
  local actual
  actual=$(wc -c < "$path")
  if [ "$actual" -ne "$bytes" ]; then
    echo "FAIL: $path is $actual bytes, expected $bytes" >&2
    exit 1
  fi
  printf '  %-24s %10d bytes\n' "$path" "$actual"
}

echo "generating payloads:"
gen data/payload_10k.bin  $((10 * 1024))
gen data/payload_100k.bin $((100 * 1024))
gen data/payload_1m.bin   $((1024 * 1024))
gen data/payload_10m.bin  $((10 * 1024 * 1024))

printf '  %-24s %10d bytes\n' data/msg.txt "$(wc -c < data/msg.txt)"
