# The Plaso image the extract_*.sh builders run, sourced by each of them. It is pinned by its digest, so every run
# uses the same build of Plaso (20260720) and dfVFS (20260717). The builders run it with --pull never and download
# nothing, so pull it once before the first run:
#   docker pull log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950
PLASO_IMAGE="log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950"
# The builders keep only the last two lines of image_export's output, which drops docker run's "No such image" error,
# so a missing image stops the builder here with the pull command. docker image inspect reads only the images already
# on the machine.
docker image inspect "$PLASO_IMAGE" >/dev/null 2>&1 || {
  echo "Plaso image $PLASO_IMAGE not found, or Docker isn't running. Pull it first: docker pull $PLASO_IMAGE"
  exit 1
}
