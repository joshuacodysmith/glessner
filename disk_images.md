# Get a triage folder from a disk image

Glessner reads a folder of collected files, with one top-level folder per host. It doesn't read a disk image's file system. When the evidence folder holds disk images, the start page's evidence check names up to three, each with its format, counts the rest, and says to mount or extract each one first.

This page gives one route from an E01 or raw image of a Windows disk to a host folder Glessner reads. The route uses the builder scripts in [scripts/](scripts/), which run [Plaso](https://github.com/log2timeline/plaso)'s `image_export` in Docker. An earlier version of these scripts built the PC's folder for the [Data Leakage Case check](checks/cfreds_data_leakage.md).

## Formats the start page names

Intake recognizes these formats by their signatures, and a raw image also by its name. The builders read the first two rows' images when they hold an NTFS volume.

| The start page names | The builders | What to do |
|---|---|---|
| `E01 segment N` | Read it when its first segment's name ends in `.E01`, in capitals. The scripts don't find a first segment named `.e01`, or a SMART image's `.s01`, which the start page also names this way | Put every segment of the image in one folder and run the builders on that folder. For an image the scripts don't find, follow the last row. |
| `raw image, NTFS volume`, `raw image, MBR disk`, `raw image, GPT disk`, or `raw image` alone, which intake gives when it finds a boot signature but can't tell what the first sectors hold | Read it when its name ends in `.001`, `.dd`, `.raw`, or `.img`, in lowercase | Run the builders on the image's folder. A split raw image's segments, `.001` on, go in one folder. |
| `raw image, FAT volume` or `raw image, exFAT volume` | Stop: `extract_e01.sh` exits 1 before it writes the triage folder, and the other builders start from that folder. The paragraph under this table gives the causes seen | Read its files with a tool built for that file system. |
| `raw image, ReFS volume` | Can't read it: dfVFS, the library `image_export` uses, has no ReFS reader in the pinned image | Extract its files with a tool that reads ReFS. A ReFS volume's extracted files hold no `$MFT` or `$J` for the file system tools. |
| `L01 segment N`, `Lx01`, `AD1 logical image` | Can't read it: a logical image holds files, not a volume | Export its files with a tool that reads the format, and put each host's files in a folder of their own. |
| `Ex01`, `VHD, dynamic`, `VHD, fixed`, `VHDX`, `VMDK sparse extent`, `VMDK descriptor`, `QCOW` | Don't take it: the scripts look only for a first file named `*.E01`, `*.001`, `*.dd`, `*.raw`, or `*.img` | Mount the image read-only, or convert it to a raw image, with a tool that reads the format. Then collect the host's files, including `$MFT` and `$J`, with a tool that reads them from the volume. |

An image the scripts take can still fail. When `image_export` can't read an image, it can exit 1 after its first log line with no message, and the builder stops. The builders stopped on all three removable-media images of the Data Leakage Case, each run with a host name. On the exFAT and UDF images, `image_export` exited 1 that way. On the FAT image, it exported no file, and `export_mft.py` then failed with "invalid volume system signature". Without a host name, `extract_e01.sh` stops sooner on an image with no SYSTEM hive, since `computer_name.py` has no hive to read the name from.

## What you need

| Part | Version tested | What it's for | License |
|---|---|---|---|
| [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) | 4.78.0 | Runs the Plaso image | Free for personal use, education, non-commercial open source projects, and businesses with fewer than 250 employees and less than $10 million in annual revenue. Larger businesses and government entities need a paid subscription. See the [Docker Desktop license agreement](https://docs.docker.com/subscription/desktop-license/). |
| The Plaso image, `log2timeline/plaso` | Plaso 20260720 and dfVFS 20260717, pinned by digest in `scripts/plaso_image.sh` | Reads the image and exports the files | [Plaso](https://github.com/log2timeline/plaso/blob/main/LICENSE) and [dfVFS](https://github.com/log2timeline/dfvfs/blob/main/LICENSE) are under the Apache License 2.0. |
| Git Bash, from [Git for Windows](https://gitforwindows.org/) | 2.55.0.windows.3 | Runs the scripts | Git is under the GNU General Public License version 2. Git for Windows ships Bash and other components under their own licenses, as its [release notes](https://github.com/git-for-windows/build-extra/blob/master/ReleaseNotes.md#licenses) list. |

The scripts run Docker with `--pull never`, so they download nothing. A script that doesn't find the pinned image stops and prints the command that pulls it. Pull the pinned image once, in Git Bash or PowerShell, before the first run:

```bash
docker pull log2timeline/plaso@sha256:a8d42e64dcd3af2dffed8ddb25d34f34def69b672eec97ea9af62885c9332950
```

The image takes 663 MB on disk.

## Build the triage folder

1. Record the image's details in your notes before you start: its file names, the hashes your imaging tool reported, and the SHA-256 of each segment. Nothing in the case ties the triage folder to the image except these notes, the hash lists the scripts keep, and the scripts' output you save in steps 3 and 4 (see [What the case can't show](#what-the-case-cant-show)).
2. Put the image's segments in a folder that holds only that image. The scripts take the first file named `*.E01`, then `*.001`, `*.dd`, `*.raw`, or `*.img`, in that order. They mount the folder read-only in the container.
3. In Git Bash, from the Glessner folder, run `extract_e01.sh` with the image's folder and a dataset folder. Save its output to a log in your notes folder, here `C:\Notes`, which must already exist:

   ```bash
   scripts/extract_e01.sh /c/Images/PC01 /c/Evidence/CASE01 2>&1 | tee -a /c/Notes/PC01_builders.log
   ```

   It writes `triage/HOST/` in the dataset folder, with `HOST` the computer name from the image's SYSTEM hive, and prints that name on its `host:` line. To choose the folder's name yourself, give it as a third argument. The script stops if the host's folder already exists. Its last line gives the folder's file count and size. The output also gives the size and SHA-256 of the `$MFT` the script copies. That line is the only record of the `$MFT`'s hash, since Plaso's hash lists don't cover it.
4. Run the other builders if you want their files. Each takes the same image folder and dataset folder, and the host folder's name from `extract_e01.sh`'s `host:` line. In this example the line read `host: PC01`. Save their output to the same log, since it holds the only record of the SHA-256 of `$J` and `$LogFile`:

   ```bash
   scripts/extract_more.sh /c/Images/PC01 /c/Evidence/CASE01 PC01 2>&1 | tee -a /c/Notes/PC01_builders.log
   scripts/extract_app_dbs.sh /c/Images/PC01 /c/Evidence/CASE01 PC01 2>&1 | tee -a /c/Notes/PC01_builders.log
   scripts/extract_wide.sh /c/Images/PC01 /c/Evidence/CASE01 PC01 2>&1 | tee -a /c/Notes/PC01_builders.log
   ```

5. On the start page, choose the folder that holds the host folders as the evidence folder: `C:\Evidence\CASE01\triage`, or `triage_more` or `wide` if you ran those builders.

Each builder also leaves a working copy of its export in the dataset's `collection` folder. Glessner doesn't read it.

On the [Stolen Szechuan Sauce](https://dfirmadness.com/the-stolen-szechuan-sauce/) case's domain controller image, an E01 of 4.9 GB in two segments, `extract_e01.sh` took 53 seconds and wrote 125 files, 198.8 MB.

## What each builder collects

| Script | Writes | What it collects |
|---|---|---|
| `extract_e01.sh IMAGE DATASET [HOST]` | `triage/HOST/` | Event logs, prefetch files, and system and user registry hives, through Plaso's artifact definitions `WindowsEventLogs`, `WindowsPrefetchFiles`, `WindowsSystemRegistryFiles`, and `WindowsUserRegistryFiles`. User LNK files from each profile's Recent, Office Recent, and Desktop folders (`lnk_filter.yaml`). The largest partition's `$MFT` (`export_mft.py`). |
| `extract_more.sh IMAGE DATASET HOST` | `triage_more/HOST/`: a copy of `triage/HOST/` plus these files | Amcache.hve, Recycle Bin `$I` and INFO2 files, jump lists, SRUDB.dat, RecentFileCache.bcf, the Windows Timeline database, and the largest partition's `$J` (`export_ntfs_stream.py`). Run `extract_e01.sh` first. |
| `extract_app_dbs.sh IMAGE DATASET HOST` | Added to `triage_more/HOST/` | Chrome, Edge, and Brave history and shortcuts, Firefox places and downloads, Windows notifications, and the Windows Timeline database, each with its write-ahead log or journal (`app_db_filter.yaml`). Files already in the folder are kept. Run `extract_more.sh` first, and don't run it on a folder a case already reads. |
| `extract_wide.sh IMAGE DATASET HOST [EXPORT]` | `wide/HOST/`: a copy of `triage_more/HOST/` plus these files | Sources Glessner doesn't read yet, such as PowerShell console history, scheduled task XML, the WMI repository, Windows Error Reporting files, the Windows Search index, and Office, XPS, and PDF documents in each user's Documents, Desktop, and Downloads folders (`wide_gap_filter.yaml`). The largest partition's `$LogFile`. It first prints each partition's count of volume shadow copy stores. Run `extract_more.sh` first. |

Each host folder keeps Plaso's hash lists, renamed `_plaso_export_hashes.json`, `_plaso_export_hashes_lnk.json`, and so on. Each list gives the SHA-256 of every file its export wrote, with the file's path in the export, which follows its path in the image. `export_mft.py` and `export_ntfs_stream.py` copy `$MFT`, `$J`, and `$LogFile`, which aren't in Plaso's lists. They print each file's size and SHA-256 to the builder's output and save it nowhere else.

## What the case can't show

The step from image to folder happens outside Glessner, so the case can't vouch for it.

- **Custody.** Intake hashes the folder's files, not the image. The only link from the case to the image is your notes, Plaso's per-file hash lists, and the builders' output. Plaso's lists don't cover `$MFT`, `$J`, or `$LogFile`, whose SHA-256 appears only in the builders' output. Keep that output, the commands you ran, the time you ran them, and the Plaso image's digest with your notes.
- **File times.** Each file in a host folder carries, as its created, modified, and accessed times, the time a builder copied it into that folder. These aren't its times on the image. `extract_more.sh` and `extract_wide.sh` copy every file of the folder they start from, so each file they put in `triage_more` or `wide` carries the time that builder ran, even when an earlier builder exported it. A file `extract_app_dbs.sh` adds to `triage_more` carries the time it ran. LECmd's source file times, such as `SourceCreated`, read the day you ran the builder that made the folder you take in. Take a file's times from the `$MFT`'s records or from the times stored inside the artifact.
- **Shadow copies.** The scripts pass `--vss_stores none`, so no volume shadow copy is exported. Older copies of event logs and hives in a store stay in the image. `extract_wide.sh` prints how many stores each partition holds, so you know what was left behind.
- **One partition's file system metadata.** `image_export` writes every partition's files into one folder tree, so where two partitions hold a file at the same path, only one copy is kept. The scripts copy `$MFT`, `$J`, and `$LogFile` from the largest partition only.
- **Deleted files and unallocated space.** The scripts export allocated files. They don't recover deleted files or carve unallocated space. Deleted files' names and times can still load from `$MFT` entries no longer in use and from `$J`.
- **Names.** Plaso writes each `$` in an exported file or folder name as `_`, wherever it appears. It does the same for control characters and for `!`, `%`, `&`, `*`, `+`, `:`, `;`, `<`, `>`, `?`, `@`, `|`, and `~`. `extract_more.sh` puts the `$` back on the Recycle Bin's folder and `$I` files, and the copied `$MFT`, `$J`, and `$LogFile` keep theirs.
