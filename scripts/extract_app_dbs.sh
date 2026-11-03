#!/bin/bash
# Add the application databases SQLECmd and WxTCmd read to a host's triage_more folder: Chrome, Edge, and Brave
# history and shortcuts, Firefox places and downloads, Windows notifications, and the Windows Timeline database, with
# their write-ahead logs and journals, which can hold the latest records (app_db_filter.yaml).
# They go to <dataset>/collection/<HOST>_apps/, then into <dataset>/triage_more/<HOST>/ at their paths. Files already
# there are kept, and no file is changed: a case taken in from triage_more sees the new ones as evidence added later.
# Don't run it on a triage_more folder a working case is reading from.
# Usage: scripts/extract_app_dbs.sh <folder holding the .E01 segments, or a raw image> <dataset folder> <HOST>
set -euo pipefail
IMG_DIR="$1"; DS_DIR="$2"; HOST="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/plaso_image.sh"
# cygpath -a makes a relative image or dataset path absolute. Docker's -v reads a relative one as a volume name.
IMAGES="$(cygpath -am "$IMG_DIR")"; DS="$(cygpath -am "$DS_DIR")"; SCRIPTS="$(cygpath -m "$HERE")"
# The first E01 segment, or else a raw image or its first split segment (.001), which Plaso and dfVFS also read. The
# patterns are tried in this order, so an E01 is taken over a raw image whose name sorts before it.
E01=$(cd "$IMG_DIR" && shopt -s nullglob && for p in *.E01 *.001 *.dd *.raw *.img; do echo "$p"; break; done || true)
[ -n "$E01" ] || { echo "no .E01, .001, .dd, .raw, or .img image in $IMG_DIR"; exit 1; }
APPS="$DS_DIR/collection/${HOST}_apps"; T="$DS_DIR/triage_more/$HOST"
[ ! -e "$APPS" ] || { echo "$APPS already exists"; exit 1; }
[ -d "$T" ] || { echo "$T not found; run extract_more.sh first"; exit 1; }

echo "image: $E01"
# --include_duplicates keeps a file whose content matches one already exported, such as an empty write-ahead log. A
# file whose output path an earlier file took, such as the same path on another partition, is still skipped.
MSYS_NO_PATHCONV=1 docker run --rm --pull never -v "$IMAGES:/evidence:ro" -v "$DS/collection:/collection" \
  -v "$SCRIPTS:/scripts:ro" "$PLASO_IMAGE" image_export.py -f /scripts/app_db_filter.yaml --vss_stores none \
  --partitions all --include_duplicates -w "/collection/${HOST}_apps" "/evidence/$E01" 2>&1 | grep -v "^Waiting" | tail -2
mkdir -p "$APPS"   # image_export may write nothing when an image holds none of these databases
[ ! -f "$APPS/hashes.json" ] || mv "$APPS/hashes.json" "$APPS/_plaso_export_hashes_apps.json"
cp -rn "$APPS/." "$T/"
echo "added to triage_more/$HOST:"
(cd "$APPS" && find . -type f ! -name '_plaso_export_hashes_apps.json' | sed 's|^\./|  |' | sort)
