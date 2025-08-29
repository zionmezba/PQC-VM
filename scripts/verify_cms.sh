#!/usr/bin/env bash
set -euo pipefail
SIG=${1:?Usage: verify_cms.sh <sigfile> [content]}
CONTENT=${2:-data/msg.txt}
openssl cms -verify -inform DER -in "$SIG" -content "$CONTENT" -purpose any > /dev/null