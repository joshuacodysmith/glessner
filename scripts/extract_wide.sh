#!/bin/bash
# Build a wide collection for one host: the sources the app reads, from <dataset>/triage_more/<HOST>/, plus the
# sources and user files it doesn't read yet (wide_gap_filter.yaml) and the largest partition's $LogFile. First it
# prints each partition's count of volume shadow copy stores, which it doesn't export. Plaso's export goes to the
# export folder, by default <dataset>/collection/<HOST>_wide/. Then <dataset>/wide/<HOST>/ gets a copy of
# triage_more/<HOST>/ plus the export, never overwriting the triage_more copies, with Plaso's hash list renamed
# _plaso_export_hashes_wide.json. The triage_more folder, and the cases built on it, stay as they are.
# Usage: scripts/extract_wide.sh <folder holding the .E01 segments, or a raw image> <dataset folder> <HOST> [export folder]
# The image folder is mounted read-only in the Plaso container. Existing folders are never overwritten.
set -euo pipefail
IMG_DIR="$1"; DS_DIR="$2"; HOST="$3"; EXPORT="${4:-$DS_DIR/collection/${HOST}_wide}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/plaso_image.sh"
# cygpath -a makes a relative image path absolute. Docker's -v reads a relative one as a volume name.
IMAGES="$(cygpath -am "$IMG_DIR")"; SCRIPTS="$(cygpath -m "$HERE")"
# The first E01 segment, or else a raw image or its first split segment (.001), which Plaso and dfVFS also read. The
# patterns are tried in this order, so an E01 is taken over a raw image whose name sorts before it.
E01=$(cd "$IMG_DIR" && shopt -s nullglob && for p in *.E01 *.001 *.dd *.raw *.img; do echo "$p"; break; done || true)
[ -n "$E01" ] || { echo "no .E01, .001, .dd, .raw, or .img image in $IMG_DIR"; exit 1; }
W="$DS_DIR/wide/$HOST"
for d in "$EXPORT" "$W"; do [ ! -e "$d" ] || { echo "$d already exists"; exit 1; }; done
[ -d "$DS_DIR/triage_more/$HOST" ] || { echo "$DS_DIR/triage_more/$HOST not found; run extract_more.sh first"; exit 1; }
mkdir -p "$(dirname "$EXPORT")"
OUT="$(cygpath -m "$(cd "$(dirname "$EXPORT")" && pwd)")"; NAME="$(basename "$EXPORT")"

plaso() {  # plaso <extra docker args...> "$PLASO_IMAGE" <command args...>
  MSYS_NO_PATHCONV=1 docker run --rm --pull never -v "$IMAGES:/evidence:ro" -v "$OUT:/out" \
    -v "$SCRIPTS:/scripts:ro" "$@"
}

echo "image: $E01"
plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/vss_stores.py "/evidence/$E01"
# --include_duplicates keeps a file whose content matches one already exported, such as an empty log. A file whose
# output path an earlier file took, such as the same path on another partition, is still skipped.
plaso "$PLASO_IMAGE" image_export.py -f /scripts/wide_gap_filter.yaml --vss_stores none --partitions all \
  --include_duplicates -w "/out/$NAME" "/evidence/$E01" 2>&1 | grep -v "^Waiting" | tail -2
mkdir -p "$EXPORT"   # image_export may write nothing when an image holds none of these sources
[ ! -f "$EXPORT/hashes.json" ] || mv "$EXPORT/hashes.json" "$EXPORT/_plaso_export_hashes_wide.json"

# $LogFile from the largest partition, the one extract_e01.sh takes $MFT from, placed beside $MFT at the host root.
PART=$(plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_mft.py --largest "/evidence/$E01" | tr -d '\r')
echo "largest partition: $PART"
plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_ntfs_stream.py "/evidence/$E01" "$PART" \
  '\$LogFile' '' "/out/$NAME/\$LogFile"

mkdir -p "$W"
cp -r "$DS_DIR/triage_more/$HOST/." "$W/"
cp -rn "$EXPORT/." "$W/"
printf "%s: %s files, %s, of which %s from the export\n" "wide/$HOST" "$(find "$W" -type f | wc -l)" \
  "$(du -sh "$W" | cut -f1)" "$(find "$EXPORT" -type f | wc -l)"
