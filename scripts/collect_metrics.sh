#!/usr/bin/env bash
set -euo pipefail
CONTENT=${1:-data/msg.txt}
ALG_LIST=${2:-"dilithium3 falcon512 sphincs+-sha2-128s-simple"}
RESULTS=results/metrics.csv
mkdir -p results out


# Header
if [ ! -f "$RESULTS" ]; then
echo "mode,alg,bytes,sign_ms,verify_ms,pass,file" > "$RESULTS"
fi


time_cmd() {
# prints milliseconds to stdout
local cmd=("$@")
local t0 t1 dt
t0=$(python3 - <<'PY'
import time
print(int(time.perf_counter()*1000))
PY
)
if "${cmd[@]}"; then
:
else
return 2
fi
t1=$(python3 - <<'PY'
import time
print(int(time.perf_counter()*1000))
PY
)
dt=$((t1 - t0))
echo "$dt"
}


run_case() {
local MODE=$1 ALG=$2
local sig
sig=$(scripts/sign_cms.sh "$CONTENT" "$MODE" "$ALG")
local size=$(stat -c%s "$sig")
local vms=; local status=1
if vms=$(time_cmd scripts/verify_cms.sh "$sig" "$CONTENT" 2>/dev/null); then
status=1
else
# verification failed
status=0
fi
echo "$MODE,$ALG,$size,,${vms},${status},$sig" >> "$RESULTS"
}


# Generate rows
# classical-only
run_case classical none


# pqc-only and hybrid for each ALG
for ALG in $ALG_LIST; do
run_case pqc $ALG
run_case hybrid $ALG
done


echo "Metrics appended to $RESULTS"