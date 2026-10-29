#!/usr/bin/env bash
# dossal bench — runs the evaluation contract, appends to ledger
cd "$(dirname "$0")"
PY=/Users/yeoreum/.hermes/tools/python-3.14.9+202****1021-darwin-arm64/bin/python3
OUT=$($PY bench.py 2>&1)
echo "$OUT"
SCORE=$(echo "$OUT" | grep 'TOTAL SCORE:' | awk '{print $3}')
COMMIT=$(git log --oneline -1 | awk '{print $1}')
TS=$(date '+%H:%M:%S')
echo -e "$COMMIT\t$SCORE\t$TS\t$1" >> loop-ledger.tsv
echo "Ledger: $COMMIT score=$SCORE"
