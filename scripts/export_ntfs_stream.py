"""Copy one NTFS file or named data stream out of one partition of a disk image, such as the USN journal's $J. Runs
inside the Plaso container, like export_mft.py, whose image and partition handling it follows.

Usage: python3 export_ntfs_stream.py <image.E01, or a raw image> <partition id> <NTFS path> <stream, or ""> <output file>
The partition id is one such as p2, or "volume" for an image of one volume, as export_mft.py --largest prints it.
Example: python3 export_ntfs_stream.py /evidence/x.E01 p2 '\\$Extend\\$UsnJrnl' '$J' /collection/HOST_more/$J

Plaso's NTFSUSNJournal artifact names $UsnJrnl but not its $J stream, which holds the change records. $J is sparse:
its leading part reads as zeros. The copy keeps it whole, as a collection tool would, so offsets stay as recorded.
"""
import hashlib
import sys

from dfvfs.lib import definitions
from dfvfs.path import factory
from dfvfs.resolver import resolver


def ewf_spec(image):
    """The image's storage media: EWF for .E01, raw otherwise. dfVFS's raw type also reads split raw images (.001)."""
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=image)
    kind = definitions.TYPE_INDICATOR_EWF if image.lower().endswith(".e01") else definitions.TYPE_INDICATOR_RAW
    return factory.Factory.NewPathSpec(kind, parent=spec)


def copy_stream(image, partition, location, stream, out):
    if partition == "volume":   # export_mft.py --largest says so for an image of one volume, with no partition table
        spec = ewf_spec(image)
    else:
        spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location="/" + partition,
                                           parent=ewf_spec(image))
    kwargs = {"data_stream": stream} if stream else {}
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location=location, parent=spec, **kwargs)
    src = resolver.Resolver.OpenFileObject(spec)
    digest, size = hashlib.sha256(), 0
    with open(out, "wb") as dst:
        while chunk := src.read(4 * 1024 * 1024):
            dst.write(chunk)
            digest.update(chunk)
            size += len(chunk)
    print(f"{out} {size} bytes sha256 {digest.hexdigest()}")


if __name__ == "__main__":
    copy_stream(*sys.argv[1:6])
