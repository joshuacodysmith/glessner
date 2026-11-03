"""Count the volume shadow copy stores on each partition of a disk image, without exporting them. Runs inside the
Plaso container, like export_ntfs_stream.py, whose image handling it shares.

Usage: python3 vss_stores.py <image.E01, or a raw image>
Prints one line per partition, or one for an image of a single volume: its id, its size in bytes, its store count,
and each store's creation time in UTC.
"""
import sys

from dfdatetime import filetime
from dfvfs.analyzer import analyzer
from dfvfs.lib import definitions, errors
from dfvfs.path import factory
from dfvfs.volume import tsk_volume_system, vshadow_volume_system
from export_ntfs_stream import ewf_spec


def partitions(image):
    """(id, size in bytes, path spec) for each partition, or ("volume", size, spec) for an image of one volume."""
    media = ewf_spec(image)
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location="/", parent=media)
    volumes = tsk_volume_system.TSKVolumeSystem()
    try:
        volumes.Open(spec)
    except errors.BackEndError:
        return [("volume", None, media)]
    return [(volume.identifier, volume.extents[0].size,
             factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location="/" + volume.identifier,
                                         parent=media))
            for volume in volumes.volumes]


def store_times(partition_spec):
    """The creation time of each shadow copy store on the partition, oldest first; empty when it holds none."""
    if definitions.TYPE_INDICATOR_VSHADOW not in analyzer.Analyzer.GetVolumeSystemTypeIndicators(partition_spec):
        return []
    spec = factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_VSHADOW, location="/", parent=partition_spec)
    stores = vshadow_volume_system.VShadowVolumeSystem()
    stores.Open(spec)
    times = (store.GetAttribute("creation_time").value for store in stores.volumes)
    return sorted(filetime.Filetime(timestamp=value).CopyToDateTimeStringISO8601() for value in times)


def main(image):
    for identifier, size, spec in partitions(image):
        times = store_times(spec)
        print(f"{identifier} {size if size is not None else '-'} bytes: {len(times)} shadow copy stores")
        for created in times:
            print(f"  created {created}")


if __name__ == "__main__":
    main(sys.argv[1])
