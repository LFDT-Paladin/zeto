#!/bin/bash
# Compile every circuit referenced (directly or via *_batch) by gen-config.json
# and report the minimum required ptau exponent based on the constraint count.
#
# Snarkjs Groth16 sizes the trusted-setup domain as
#   2^N >= nConstraints + nPublicInputs + nOutputs + 1
# So the minimum N = ceil(log2(nConstraints + nPubInputs + nOutputs + 1)).

set -e
cd /Users/jimzhang/workspace.zkp/zeto/zkp/circuits
mkdir -p /tmp/zeto-r1cs

node -e "
const c = require('./scripts/gen-config.json').circuits;
const out = [];
for (const [name, cfg] of Object.entries(c)) {
  out.push([name, cfg.ptau]);
  if (cfg.batchPtau) out.push([name + '_batch', cfg.batchPtau]);
}
for (const [n, p] of out) console.log(n, p);
" > /tmp/zeto-r1cs/circuits.list

printf '%-50s %-12s %-10s %-10s %-10s %-10s %s\n' \
  "CIRCUIT" "CONSTRAINTS" "PUB_IN" "OUTPUTS" "MIN_PTAU" "CFG_PTAU" "STATUS"
printf '%s\n' "----------------------------------------------------------------------------------------------------------------"

while read -r circuit configured; do
  src="${circuit}.circom"
  if [ ! -f "$src" ]; then
    printf '%-50s MISSING SOURCE: %s\n' "$circuit" "$src"
    continue
  fi
  r1cs="/tmp/zeto-r1cs/${circuit}.r1cs"
  if [ ! -f "$r1cs" ]; then
    circom "$src" --r1cs --output /tmp/zeto-r1cs >/dev/null 2>&1 || {
      printf '%-50s COMPILE FAILED\n' "$circuit"; continue;
    }
  fi
  info=$(npx --no-install snarkjs r1cs info "$r1cs" 2>&1 | sed -E 's/\x1b\[[0-9;]*[mGKHJ]//g')
  cnt=$(echo "$info" | awk '/# of Constraints:/ {n=$NF; gsub(/[^0-9]/,"",n); print n; exit}')
  pub=$(echo "$info" | awk '/# of Public Inputs:/ {n=$NF; gsub(/[^0-9]/,"",n); print n; exit}')
  outs=$(echo "$info" | awk '/# of Outputs:/ {n=$NF; gsub(/[^0-9]/,"",n); print n; exit}')
  cnt=${cnt:-0}; pub=${pub:-0}; outs=${outs:-0}
  if [ -z "$cnt" ]; then
    printf '%-50s INFO PARSE FAIL\n' "$circuit"; continue;
  fi
  needed=$((cnt + pub + outs + 1))
  min_ptau=$(python3 -c "import math; print(max(1, math.ceil(math.log2($needed))))")
  cfg_n=$(echo "$configured" | awk -F_ '{print $NF}')
  status="ok"
  if [ "$min_ptau" -lt "$cfg_n" ]; then
    status="OVERSIZED -> can drop to _${min_ptau}"
  elif [ "$min_ptau" -gt "$cfg_n" ]; then
    status="TOO SMALL -> must raise to >= _${min_ptau}"
  fi
  printf '%-50s %-12s %-10s %-10s %-10s %-10s %s\n' \
    "$circuit" "$cnt" "$pub" "$outs" "$min_ptau" "$cfg_n" "$status"
done < /tmp/zeto-r1cs/circuits.list
