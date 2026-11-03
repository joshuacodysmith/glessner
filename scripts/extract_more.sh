#!/bin/bash
# Add more artifacts to a host that extract_e01.sh built: Amcache.hve, Recycle Bin $I and INFO2 files, jump lists,
# SRUDB.dat, RecentFileCache.bcf, the Windows Timeline database, and the USN journal's $J.
# They go to <dataset>/collection/<HOST>_more/. Then <dataset>/triage_more/<HOST>/ gets a whole triage folder: a copy
# of triage/<HOST> plus these files. The existing triage folder, and the cases built on it, stay as they are.
# Usage: scripts/extract_more.sh <folder holding the .E01 segments, or a raw image> <dataset folder> <HOST>
# The image folder is mounted read-only in the Plaso container. Existing folders are never overwritten.
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
MORE="$DS_DIR/collection/${HOST}_more"; T="$DS_DIR/triage_more/$HOST"
for d in "$MORE" "$T"; do [ ! -e "$d" ] || { echo "$d already exists"; exit 1; }; done
[ -d "$DS_DIR/triage/$HOST" ] || { echo "$DS_DIR/triage/$HOST not found; run extract_e01.sh first"; exit 1; }

plaso() {  # plaso <extra docker args...> "$PLASO_IMAGE" <command args...>
  MSYS_NO_PATHCONV=1 docker run --rm --pull never -v "$IMAGES:/evidence:ro" -v "$DS/collection:/collection" \
    -v "$SCRIPTS:/scripts:ro" "$@"
}

echo "image: $E01"
# --include_duplicates keeps a file whose content matches one already exported. A file whose output path an earlier
# file took, such as the same path on another partition, is still skipped.
plaso "$PLASO_IMAGE" image_export.py --artifact_filters \
  WindowsAMCacheHveFile,WindowsRecycleBinMetadata,WindowsUserJumpLists,WindowsSystemResourceUsageMonitorDatabaseFile,WindowsRecentFileCacheBCF,WindowsActivitiesCacheDatabase \
  --vss_stores none --partitions all --include_duplicates -w "/collection/${HOST}_more" "/evidence/$E01" 2>&1 \
  | grep -v "^Waiting" | tail -2
mkdir -p "$MORE"   # image_export may write nothing when an image holds none of these artifacts
[ ! -f "$MORE/hashes.json" ] || mv "$MORE/hashes.json" "$MORE/_plaso_export_hashes_more.json"

# $J from the largest partition, the same one extract_e01.sh takes $MFT from, placed beside $MFT at the host root.
PART=$(plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_mft.py --largest "/evidence/$E01" | tr -d '\r')
echo "largest partition: $PART"
plaso --entrypoint python3 "$PLASO_IMAGE" /scripts/export_ntfs_stream.py "/evidence/$E01" "$PART" \
  '\$Extend\$UsnJrnl' '$J' "/collection/${HOST}_more/\$J"

mkdir -p "$T"
cp -r "$DS_DIR/triage/$HOST/." "$T/"
# The artifact groups also export hives the triage folder already holds. -n keeps the triage folder's copies.
cp -rn "$MORE/." "$T/"
# Plaso writes $ as _ in exported names. A collection keeps $Recycle.Bin and $I names, and RBCmd looks for them.
if [ -d "$T/_Recycle.Bin" ]; then
  mv "$T/_Recycle.Bin" "$T/\$Recycle.Bin"
  find "$T/\$Recycle.Bin" -type f -name '_I*' | while read -r f; do mv "$f" "$(dirname "$f")/\$${f##*/_}"; done
fi
printf "%s: %s files, %s\n" "triage_more/$HOST" "$(find "$T" -type f | wc -l)" "$(du -sh "$T" | cut -f1)"
