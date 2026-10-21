#!/bin/bash
# Performance check: build a 10-host collection from the two Szechuan Sauce hosts (four renamed
# copies of each), then run intake and all six tools, timing each step in whole seconds. Writes
# timings.tsv in the case folder.
# The copies have the same names and IPs inside their artifacts, so host identity sees conflicts and
# links between copies do not resolve. That does not affect the load and query timings this measures.
set -euo pipefail
SRC=/d/DFIR-Lab/datasets/szechuan-sauce/triage
DST=/d/DFIR-Lab/datasets/szechuan-sauce/triage10
CASE_POSIX=/d/DFIR-Lab/cases/perf-10-hosts
CASE='D:\DFIR-Lab\cases\perf-10-hosts'
PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -e "$DST" ] && { echo "$DST exists"; exit 1; }
[ -e "$CASE_POSIX" ] && { echo "case exists"; exit 1; }

start=$(date +%s)
mkdir -p "$DST"
for host in DC01 DESKTOP; do
  cp -rp "$SRC/$host" "$DST/$host"
  for n in 2 3 4 5; do cp -rp "$SRC/$host" "$DST/$host-C$n"; done
done
copy_seconds=$(( $(date +%s) - start ))

cd "$PROJECT"
uv run glessner new-case "$CASE" --evidence 'D:\DFIR-Lab\datasets\szechuan-sauce\triage10' \
  --name "Performance check, 10 hosts" --analyst perf --tools 'D:\DFIR-Lab\tools'
TIMINGS="$CASE_POSIX/timings.tsv"
printf "step\tseconds\ncopy\t%s\n" "$copy_seconds" > "$TIMINGS"
start=$(date +%s); uv run glessner intake "$CASE" | head -3
printf "intake\t%s\n" "$(( $(date +%s) - start ))" >> "$TIMINGS"
for tool in evtxecmd hayabusa recmd mftecmd pecmd lecmd; do
  start=$(date +%s)
  uv run glessner run "$CASE" --tool "$tool" | grep -v "run record"
  printf "%s\t%s\n" "$tool" "$(( $(date +%s) - start ))" >> "$TIMINGS"
done
cat "$TIMINGS"
