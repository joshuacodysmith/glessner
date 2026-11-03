"""Copy $MFT from one partition of a disk image. Runs inside the Plaso container, which ships dfVFS.

Usage:
  python3 export_mft.py <image.E01, or a raw image> <partition id, such as p2> <output file>
  python3 export_mft.py --largest <image.E01, or a raw image>    prints the id of the largest partition, or "volume"
                                                                 for an image of one volume

Plaso's image_export writes every partition's $MFT to one output path, so on a disk with a small system partition
the copy left there can be that partition's. This copies one partition's $MFT and prints its size and SHA-256.
"""
import hashlib
import sys

from dfvfs.lib import definitions, errors
from dfvfs.path import factory
from dfvfs.resolver import resolver
from dfvfs.volume import tsk_volume_system


def ewf_spec(image):
    """The image's storage media: EWF for .E01, raw otherwise. dfVFS's raw type also reads split raw images (.001)."""
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=image)
    kind = definitions.TYPE_INDICATOR_EWF if image.lower().endswith(".e01") else definitions.TYPE_INDICATOR_RAW
    return factory.Factory.NewPathSpec(kind, parent=spec)


VOLUME = "volume"   # an image of one NTFS volume, with no partition table


def largest_partition(image):
    """The id of the image's largest partition, such as p2, or VOLUME for an image with no partition table."""
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location="/", parent=ewf_spec(image))
    volumes = tsk_volume_system.TSKVolumeSystem()
    try:
        volumes.Open(spec)
    except errors.BackEndError:
        return VOLUME
    return max(volumes.volumes, key=lambda v: v.extents[0].size).identifier


def volume_spec(image, partition):
    """The partition's path spec, or the image itself when it is a single volume."""
    if partition == VOLUME:
        return ewf_spec(image)
    return factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location="/" + partition,
                                       parent=ewf_spec(image))


def copy_mft(image, partition, out):
    """Copy the partition's $MFT to `out`, and print its size and SHA-256."""
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location="\\$MFT",
                                       parent=volume_spec(image, partition))
    src = resolver.Resolver.OpenFileObject(spec)
    digest, size = hashlib.sha256(), 0
    with open(out, "wb") as dst:
        while chunk := src.read(4 * 1024 * 1024):
            dst.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    print(f"{out} {size} bytes sha256 {digest.hexdigest()}")


if __name__ == "__main__":
    if sys.argv[1] == "--largest":
        print(largest_partition(sys.argv[2]))
    else:
        copy_mft(*sys.argv[1:4])
