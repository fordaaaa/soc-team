#!/bin/sh
# End-to-end demo: generate the synthetic scenario, run the detection
# engine over it, and print the alerts. Synthetic traffic only — nothing
# here touches a real network. Run from the repo root:
#
#   scripts/demo.sh [out-dir]
set -eu
OUT="${1:-/tmp/socteam-demo}"
ALERTS="$OUT-alerts"

cargo build -q -p ctl
rm -rf "$OUT" "$ALERTS"
mkdir -p "$ALERTS"

cargo run -q -p ctl -- demo --out "$OUT"
cargo run -q -p ctl -- detect --events "$OUT" \
    --out "$ALERTS/alerts-0001.ndjson" \
    --watchlist "$OUT/watchlist.txt"

echo
cargo run -q -p ctl -- alerts --events "$ALERTS"
echo
echo "JSON view:  cargo run -p ctl -- alerts --events $ALERTS --json"
echo "Console:    cargo run -p socteam-console -- --simulate --events $OUT --alerts-file $ALERTS/alerts-0001.ndjson --no-open"
