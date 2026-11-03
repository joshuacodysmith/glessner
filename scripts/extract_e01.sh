#!/bin/bash
# Build one host's triage folder from a disk image, in the layout Glessner reads: <dataset>/triage/<HOST>/ holding
# the event logs, prefetch files, system and user registry hives, and user LNK files of every partition, and the
# largest partition's $MFT. Plaso's image_export (plaso_image.sh) exports the files, lnk_filter.yaml selects the LNK
# files, and export_mft.py copies the $MFT.
# Usage: scripts/extract_e01.sh <folder holding the .E01 segments, or a raw image> <dataset folder> [HOST]
# Without HOST, the host folder takes the ComputerName from the image's SYSTEM hive.
# The image folder is mounted read-only in the Plaso container. Existing host folders are never overwritten.
set -euo pipefail
IMG_DIR="$1"; DS_DIR="$2"; HOST="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/plaso_image.sh"
# cygpath -a makes a relative image or dataset path absolute. Docker's -v reads a relative one as a volume name.
IMAGES="$(cygpath -am "$IMG_DIR")"; DS="$(cygpath -am "$DS_DIR")"; SCRIPTS="$(cygpath -m "$HERE")"
# The first E01 segment, or else a raw image or its first split segment (.001), which Plaso and dfVFS also read. The
# patterns are tried in this order, so an E01 is taken over a raw image whose name sorts before it.
E01=$(cd "$IMG_DIR" && shopt -s nullglob && for p in *.E01 *.001 *.dd *.raw *.img; do echo "$p"; break; done || true)
[ -n "$E01" ] || { echo "no .E01, .001, .dd, .raw, or .img image in $IMG_DIR"; exit 1; }
NEW="_new_$$"
mkdir -p "$DS_DIR/collection"

plaso() {  # plaso <extra docker args...> "$PLASO_IMAGE" <command args...>
  MSYS_NO_PATHCONV=1 docker run --rm --pull never -v "$IMAGES:/evidence:ro" -v "$DS/collection:/collection" \
    -v "$SCRIPTS:/scripts:ro" "$@"
}

echo "image: $E01"
# --include_duplicates keeps a file whose content matches one already exported, such as an empty event log. A file
# whose output path an earlier file took, such as the same path on another partition, is still skipped.
plaso "$PLASO_IMAGE" image_export.py --artifact_filters \
  WindowsEventLogs,WindowsPrefetchFiles,WindowsSystemRegistryFiles,WindowsUserRegistryFiles \
  --vss_stores none --partitions all --include_duplicates -w "/collection/$NEW" "/evidence/$E01" 2>&1 \
  | grep -v "^Waiting" | tail -2
if [ -z "$HOST" ]; then
  HOST=$(plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/computer_name.py \
         "/collection/$NEW/Windows/System32/config/SYSTEM" | tr -d '\r')
fi
echo "host: $HOST"
for d in "$DS_DIR/collection/$HOST" "$DS_DIR/collection/${HOST}_lnk" "$DS_DIR/collection/${HOST}_mft" "$DS_DIR/triage/$HOST"; do
  [ ! -e "$d" ] || { echo "$d already exists; the export is left in collection/$NEW"; exit 1; }
done
mv "$DS_DIR/collection/$NEW" "$DS_DIR/collection/$HOST"

plaso "$PLASO_IMAGE" image_export.py -f /scripts/lnk_filter.yaml --vss_stores none --partitions all \
  --include_duplicates -w "/collection/${HOST}_lnk" "/evidence/$E01" 2>&1 | grep -v "^Waiting" | tail -2
PART=$(plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_mft.py --largest "/evidence/$E01" | tr -d '\r')
echo "largest partition: $PART"
mkdir -p "$DS_DIR/collection/${HOST}_mft"
plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_mft.py "/evidence/$E01" "$PART" "/collection/${HOST}_mft/\$MFT"

# The triage layout: one folder per host, its LNK files and $MFT inside it, Plaso's hash lists renamed.
T="$DS_DIR/triage/$HOST"
mkdir -p "$T"
cp -r "$DS_DIR/collection/$HOST/." "$T/"
[ ! -f "$T/hashes.json" ] || mv "$T/hashes.json" "$T/_plaso_export_hashes.json"
if [ -d "$DS_DIR/collection/${HOST}_lnk" ]; then   # absent when the image holds no user LNK files
  cp -r "$DS_DIR/collection/${HOST}_lnk/." "$T/"
  [ ! -f "$T/hashes.json" ] || mv "$T/hashes.json" "$T/_plaso_export_hashes_lnk.json"
fi
cp "$DS_DIR/collection/${HOST}_mft/\$MFT" "$T/"
printf "%s: %s files, %s\n" "triage/$HOST" "$(find "$T" -type f | wc -l)" "$(du -sh "$T" | cut -f1)"
