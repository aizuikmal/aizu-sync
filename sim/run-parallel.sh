#!/usr/bin/env bash
# Usage: sim/run-parallel.sh <seeds> <steps> <workers>   (e.g. 10000 80 8)
# Splits seeds 1..N across workers; logs to sim/out/. Exit 1 if any seed failed.
set -uo pipefail
cd "$(dirname "$0")/.."
N=${1:-10000}; STEPS=${2:-80}; W=${3:-8}
per=$(( (N + W - 1) / W ))
pids=()
for ((i = 0; i < W; i++)); do
  from=$(( i * per + 1 )); to=$(( (i + 1) * per )); (( to > N )) && to=$N
  plugin/node_modules/.bin/tsx sim/run.ts --from $from --to $to --steps $STEPS > sim/out/w$i-s$STEPS.log 2>&1 &
  pids+=($!)
done
rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
tail -qn1 sim/out/w*-s$STEPS.log
grep -h "^FAIL" sim/out/w*-s$STEPS.log | cut -c1-160 | sort | uniq -c | sort -rn | head -20
exit $rc
