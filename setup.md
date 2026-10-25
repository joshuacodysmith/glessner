# Set up Glessner

This page sets up Glessner on a Windows machine that has none of its parts yet. You install the app, make a tools folder at `C:\Tools`, put the tools Glessner runs in it, and check that the app finds each one. The paths are examples. Any folder works if you use it throughout.

Each tool is optional. Glessner runs the installed tools that have evidence to read, and a missing tool means its records don't reach the timeline. `glessner tools CASE` lists what is installed.

The commands are for Windows PowerShell, which comes with Windows. Paste the blocks into one PowerShell window, in order. Step 1 has you open a new window once, after uv is installed. Only Npcap's installer needs administrator rights.

These steps were tested on 2026-10-21 on a fresh Windows 11 installation, build 26100, with the versions below.

## What you install

| Part | Version tested | What it's for | Download |
|---|---|---|---|
| uv | 0.13.4 | Installs Python and the app's dependencies, and runs the app | 15.2 MB |
| Python | 3.14.8 | Runs the app. uv installs it | 23.3 MB |
| Glessner | This repository | The app, and its Python packages, which uv installs | About 4 MB, then 65 MB of packages |
| Eric Zimmerman's tools | 2026.5.0 | Event logs, registry, $MFT and $J, Prefetch, LNK files, jump lists, shellbags, Amcache, SRUM, Recycle Bin, browser history, notifications, and the Windows Timeline | 12 zips, 47.6 MB |
| .NET 9 runtime | 9.0.21 | Runs RBCmd, SQLECmd, and WxTCmd | 36.0 MB |
| Hayabusa | 4.1.0 | Sigma and Hayabusa rule hits on event logs | 44.8 MB |
| Npcap | 1.89 | Lets Suricata read capture files | 1.3 MB |
| Suricata | 8.0.7 | Network records and alerts from packet captures | 36.7 MB |
| ET Open rule set | The current set for Suricata 8.0.7, version 11314 when tested | Suricata's alerts | 5.6 MB |

## 1. Install uv and Glessner

Install uv, following [its installation page](https://docs.astral.sh/uv/getting-started/installation/):

```powershell
winget install --id=astral-sh.uv -e
```

If the machine has no `winget`, use uv's installer script instead:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Close and reopen PowerShell, so the window finds `uv`.

Get Glessner. With Git installed, clone the repository:

```powershell
git clone https://github.com/joshuacodysmith/glessner C:\Glessner
```

Without Git, open the repository's page, choose **Code**, then **Download ZIP**, and unpack the zip to `C:\Glessner`.

Install the app's dependencies, then check that the app starts. The repository's `.python-version` file names Python 3.14, and uv downloads it for the app's own use when the machine doesn't have it:

```powershell
cd C:\Glessner
uv sync
uv run glessner --version
```

## 2. Make the tools folder

Glessner runs the executables it finds in the tools folder and its subfolders. So the tools folder must not hold, or sit inside, an evidence folder or a case folder. The blocks below make this layout:

| Folder | Contents |
|---|---|
| `C:\Tools\EZTools\` | One folder per Eric Zimmerman tool, such as `C:\Tools\EZTools\RBCmd\` |
| `C:\Tools\dotnet-9\` | The .NET 9 runtime, unpacked |
| `C:\Tools\hayabusa-4.1.0\` | Hayabusa, with its rules and config folders |
| `C:\Tools\suricata-8.0.7\` | Suricata, unpacked from its installer, with the ET Open rule set |

## 3. Eric Zimmerman's tools

Glessner uses 12 of Eric Zimmerman's command-line tools. Nine are the .NET Framework 4.7.2 builds, which run on the .NET Framework that comes with Windows 10 and 11. RBCmd, SQLECmd, and WxTCmd are the .NET 9 builds. SQLECmd and WxTCmd have no .NET 4 build. RBCmd has one, but it needs administrator rights to search a folder, and without them it finds no Recycle Bin files.

Eric's [Get-ZimmermanTools](https://github.com/EricZimmerman/Get-ZimmermanTools) script now keeps only .NET 10 builds by default, and on 2026-10-21 [his tool list](https://ericzimmerman.github.io/) had none, so its default run would download none of these tools. Use this block instead. It downloads the 12 zips from Eric's download site, unpacks each to its own folder, and checks each tool's .exe. If an .exe isn't signed by ZimTech LLC, Eric's company, the block deletes that tool's folder and stops. It doesn't check the .dll files or the other files in a zip.

```powershell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$base = 'https://download.ericzimmermanstools.com'
$tools = 'AmcacheParser', 'EvtxECmd', 'JLECmd', 'LECmd', 'MFTECmd', 'PECmd', 'RECmd', 'SBECmd', 'SrumECmd',
    'net9/RBCmd', 'net9/SQLECmd', 'net9/WxTCmd'
foreach ($tool in $tools) {
    $name = Split-Path $tool -Leaf
    $zip = Join-Path $env:TEMP "$name.zip"
    $dest = "C:\Tools\EZTools\$name"
    Invoke-WebRequest "$base/$tool.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $dest -Force
    Remove-Item $zip
    $exe = Get-ChildItem $dest -Recurse -Filter "$name.exe" | Select-Object -First 1
    if (-not $exe) { throw "$name.zip holds no $name.exe" }
    $sig = Get-AuthenticodeSignature $exe.FullName
    $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetNameInfo('SimpleName', $false) } else { 'no signer' }
    if ($sig.Status -ne 'Valid' -or $signer -ne 'ZimTech LLC') {
        Remove-Item $dest -Recurse -Force
        throw "$name is not signed by ZimTech LLC ($($sig.Status), $signer), so its folder was deleted"
    }
    "$name is signed by $signer"
}
```

To update the tools later, run the block again. It replaces each tool's files, and Glessner records the version each run used.

## 4. The .NET 9 runtime

RBCmd, SQLECmd, and WxTCmd are framework-dependent: each needs a .NET 9 runtime to start. Glessner finds a runtime unpacked in the tools folder and points those three tools at it for their runs only. Nothing is installed machine-wide.

Microsoft ends support for .NET 9 on November 10, 2026, as its [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core) states. After that date Microsoft publishes no security fixes for it, and these three tools read evidence files that may be hostile. On 2026-10-21 Eric Zimmerman's .NET 10 builds of the three tools were not yet published: their download links answered 404. Once they are, Glessner's [registry](registry/) moves to them and this step changes to the .NET 10 runtime. Until then, use the .NET 9 runtime, or leave the three tools out and work without their records.

This block reads Microsoft's release list for .NET 9, downloads the newest runtime zip for 64-bit Windows, checks it against the SHA-512 hash that the list gives, and unpacks it to `C:\Tools\dotnet-9`:

```powershell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$release = (Invoke-RestMethod 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/9.0/releases.json').releases[0]
$file = $release.runtime.files | Where-Object { $_.name -eq 'dotnet-runtime-win-x64.zip' }
$zip = Join-Path $env:TEMP 'dotnet-runtime-9-win-x64.zip'
Invoke-WebRequest $file.url -OutFile $zip -UseBasicParsing
if ((Get-FileHash $zip -Algorithm SHA512).Hash -ne $file.hash) { throw 'The runtime zip does not match the hash Microsoft lists' }
Expand-Archive -Path $zip -DestinationPath 'C:\Tools\dotnet-9' -Force
Remove-Item $zip
"Unpacked .NET runtime $($release.'release-version') to C:\Tools\dotnet-9"
```

If the machine already has the .NET 9 runtime installed from [Microsoft's .NET 9 download page](https://dotnet.microsoft.com/en-us/download/dotnet/9.0), you can skip this step. The three tools then run on the installed runtime.

## 5. Hayabusa

This block downloads Hayabusa 4.1.0 from its [GitHub release](https://github.com/Yamato-Security/hayabusa/releases/tag/v4.1.0), checks the zip against the SHA-256 digest GitHub lists for it, and unpacks it. Hayabusa's executable isn't signed, so the digest is the check.

```powershell
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$zip = Join-Path $env:TEMP 'hayabusa-4.1.0-win-x64.zip'
Invoke-WebRequest 'https://github.com/Yamato-Security/hayabusa/releases/download/v4.1.0/hayabusa-4.1.0-win-x64.zip' -OutFile $zip -UseBasicParsing
if ((Get-FileHash $zip).Hash -ne '4d304cc5baaa750ed08cc24b7b89c58ea058740c7e344502d7b82554637543a8') { throw 'The Hayabusa zip does not match its release digest' }
Expand-Archive -Path $zip -DestinationPath 'C:\Tools\hayabusa-4.1.0' -Force
Remove-Item $zip
```

The zip holds Hayabusa's rules. Updating them with `hayabusa update-rules` needs network access, and that step is yours to run.

A zip install's rules folder isn't a Git checkout, so from case format 4 Glessner names the rule set of each Hayabusa run `Hayabusa rules` plus the first 8 hex digits of the rules folder's SHA-256, such as `Hayabusa rules a1b2c3d4`. A rules folder that is a Git checkout is named by the first 7 digits of its commit and the first 8 of the folder's SHA-256, such as `Hayabusa rules fffbdd1, files 7c30c465`. A file you edit, add, or remove in the rules folder, `rules\config` included, changes the 8 digits, so an edited checkout reads differently from an unedited one at the same commit. Each run also records the SHA-256 of the `rules` and `config` folders.

## 6. Npcap, Suricata, and the ET Open rule set

Suricata reads packet captures. Its Windows build loads Npcap's `wpcap.dll` even to read capture files, so install Npcap first.

1. Download the Npcap installer from [npcap.com](https://npcap.com/#download) and run it as an administrator. The default options are enough. Glessner adds Npcap's own folder to Suricata's PATH, so the installer's WinPcap API-compatible mode isn't needed. Npcap's free edition allows five installations; [npcap.com](https://npcap.com/) gives its license terms.
2. Download Suricata's installer, which [suricata.io](https://suricata.io/download/) links, and unpack it into the tools folder, rather than installing it. Glessner finds Suricata in the tools folder and passes the paths Suricata needs on its command line, so the unpacked copy needs no installation. This block checks that the installer is signed by the Open Information Security Foundation (OISF), then unpacks it with `msiexec /a`, which copies the files and installs nothing:

   ```powershell
   $ErrorActionPreference = 'Stop'
   $ProgressPreference = 'SilentlyContinue'
   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
   $msi = Join-Path $env:TEMP 'Suricata-8.0.7-1-64bit.msi'
   Invoke-WebRequest 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.7-1-64bit.msi' -OutFile $msi -UseBasicParsing
   $sig = Get-AuthenticodeSignature $msi
   if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Open Information Security Foundation') { throw 'The Suricata installer is not signed by OISF' }
   $unpack = Start-Process msiexec.exe -ArgumentList '/a', "`"$msi`"", '/qn', 'TARGETDIR=C:\Tools\suricata-8.0.7' -Wait -PassThru
   if ($unpack.ExitCode -ne 0) { throw "msiexec stopped with exit code $($unpack.ExitCode)" }
   Remove-Item $msi
   ```

   Suricata's program is then in `C:\Tools\suricata-8.0.7\PFiles\Suricata\`.
3. Download the [ET Open rule set for Suricata 8.0.7](https://rules.emergingthreats.net/open/suricata-8.0.7/) from Proofpoint, check it against its published MD5, and unpack it beside Suricata:

   ```powershell
   $ErrorActionPreference = 'Stop'
   $ProgressPreference = 'SilentlyContinue'
   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
   $et = 'C:\Tools\suricata-8.0.7\et-open'
   $base = 'https://rules.emergingthreats.net/open/suricata-8.0.7'
   New-Item -ItemType Directory -Force $et | Out-Null
   foreach ($name in 'emerging.rules.tar.gz', 'emerging.rules.tar.gz.md5', 'version.txt') {
       Invoke-WebRequest "$base/$name" -OutFile (Join-Path $et $name) -UseBasicParsing
   }
   $md5 = (Get-Content "$et\emerging.rules.tar.gz.md5" -Raw).Trim()
   if ((Get-FileHash "$et\emerging.rules.tar.gz" -Algorithm MD5).Hash -ne $md5) { throw 'The rule set does not match its published MD5' }
   & "$env:SystemRoot\System32\tar.exe" -xzf "$et\emerging.rules.tar.gz" -C $et
   if ($LASTEXITCODE -ne 0) { throw "tar stopped with exit code $LASTEXITCODE" }
   ```

4. Build the one rule file Glessner's Suricata runs load. The script, [scripts/suricata_rules.py](scripts/suricata_rules.py), combines every rule file in the set except the ones ET has withdrawn, and writes the set's version beside it:

   ```powershell
   cd C:\Glessner
   uv run python scripts\suricata_rules.py C:\Tools\suricata-8.0.7\et-open C:\Tools\suricata-8.0.7\PFiles\Suricata
   ```

Without the rule file, Suricata still writes its network records, and raises no alerts. To refresh the rules, run steps 3 and 4 again. Each Suricata run records the rule set's version. From case format 4, each run also records the SHA-256 of the rule file, the version file, and the other files its command line names in Suricata's folder.

## 7. Check the setup

`glessner tools` reads a case's tools folder, so make a small case for the check, with an empty evidence folder:

```powershell
cd C:\Glessner
New-Item -ItemType Directory -Force C:\Evidence\SETUPCHECK | Out-Null
uv run glessner new-case C:\Cases\SETUPCHECK --evidence C:\Evidence\SETUPCHECK --name SETUPCHECK --tools C:\Tools
uv run glessner tools C:\Cases\SETUPCHECK
```

Each installed tool shows its version and the executable Glessner found. With every step above done, the list looks like this:

```text
Tools folder: C:\Tools
  AmcacheParser 2026.5.0   C:\Tools\EZTools\AmcacheParser\AmcacheParser.exe
  Windows event XML 0.1.0      C:\Glessner\.venv\Scripts\python.exe
  EvtxECmd   2026.5.0   C:\Tools\EZTools\EvtxECmd\EvtxeCmd\EvtxECmd.exe
  Hayabusa   4.1.0      C:\Tools\hayabusa-4.1.0\hayabusa-4.1.0-win-x64.exe
  JLECmd     2026.5.0   C:\Tools\EZTools\JLECmd\JLECmd.exe
  LECmd      2026.5.0   C:\Tools\EZTools\LECmd\LECmd.exe
  MFTECmd    2026.5.0   C:\Tools\EZTools\MFTECmd\MFTECmd.exe
  MFTECmd ($J) 2026.5.0   C:\Tools\EZTools\MFTECmd\MFTECmd.exe
  PECmd      2026.5.0   C:\Tools\EZTools\PECmd\PECmd.exe
  RBCmd      2026.5.0   C:\Tools\EZTools\RBCmd\RBCmd.exe
  RECmd      2026.5.0   C:\Tools\EZTools\RECmd\RECmd\RECmd.exe
  SBECmd     2026.5.0   C:\Tools\EZTools\SBECmd\SBECmd.exe
  SQLECmd    2026.5.0   C:\Tools\EZTools\SQLECmd\SQLECmd\SQLECmd.exe
  SrumECmd   2026.5.0   C:\Tools\EZTools\SrumECmd\SrumECmd.exe
  Suricata   8.0.7      C:\Tools\suricata-8.0.7\PFiles\Suricata\suricata.exe
  WxTCmd     2026.5.0   C:\Tools\EZTools\WxTCmd\WxTCmd.exe
```

Windows event XML is Glessner's own reader, so it shows the app's version, with the commit added in a Git clone. A tool that shows `unknown` was found but didn't report its version:

| Tool | What `unknown` means |
|---|---|
| RBCmd, SQLECmd, WxTCmd | No .NET 9 runtime was found. Repeat step 4, and check that `C:\Tools\dotnet-9\dotnet.exe` exists |
| Suricata | Npcap isn't installed. Install it as step 6 describes |

A tool that shows `not found` isn't in the tools folder or on the PATH. The **Tools** page, in the case's **Case** menu, shows the same list, and names the runtime each .NET tool runs on.

When the list is right, delete `C:\Cases\SETUPCHECK` and `C:\Evidence\SETUPCHECK`.

## 8. Before your first case

Keep each case folder inside a folder your antivirus excludes. Tool output quotes attacker command lines and payloads, and Windows Defender quarantines it otherwise. Whether to add an exclusion, and where, is the machine owner's decision.

The [README](README.md) shows how to make a case, run the tools, and open the timeline.
