"""File keys for Same file, and the imports' logon roles: each fills a field the pivots read, on rebuild, and none
changes an event's ID. The 8.3 names, the pivots' counts, and search and the View are tested where those are:
test_pivots.py, test_search.py, test_filters.py."""

import pivot_key_fixtures as fx
import pytest
from test_analysis_relations import open_case

from glessner.events import load
from glessner.imports import PRESETS, MappingError, normalize_mapping, split_account
from glessner.parsers.common import command_file, expand_folder, file_key, known_folder
from glessner.queries import related

# The IDs the fixtures in pivot_key_fixtures give under the parsers and the import, pinned: a mark names its event by ID.
# The ID hashes the host, artifact, source file, source record, and time description, and no file field is one of
# them. The Autoruns rows are the ones that could change: a timed row's time description follows its image path's
# extension, so a fallback key from the launch string must not be taken as the file path before that is chosen.
GOLDEN = {
    "7045 SystemRoot": "27557c711d1b70907ea1fd022b6865bb",
    "7045 x86 with a space": "727739774f4590d548150c7978f76f05",
    "7045 8.3 path": "c78ab98d4282c2ce12aa0753aacd2846",
    "4688 SystemRoot": "57ca9c76b2237c585247be6cef30b5ff",
    "shim SYSVOL": "729933b6999da71a703c53f754960851",
    "shim drive": "c426aa5e227bd284e242ce043825788a",
    "shim D drive": "0ea49411d0ce1d8545fb6978ffdab042",
    "shim packaged": "cf43c331d083458c5a533825e6bdfedb",
    "bam device path": "3d23c8413936187818d72e827ca7606d",
    "bam app ID": "02452a2a4fffb68580f8ef20a48c6cd0",
    "run quoted": "c3728f0a1cd41bef57a5245a4b769183",
    "run windir": "78e5fe719d8c76e37bfbabd4eee9521e",
    "run comspec": "0605fa17e303ab46d57301bf8108d2ad",
    "run appdata": "6c577aae16bc6ca6dafe265f92c50ff4",
    "run key only": "de31cb317ef57fca12630ff20005e9f6",
    "services svchost": "422294c221a2ccc9ae88bbc283d5c3e7",
    "services driver": "9737e6cc4d17a308f6cb45b0c369c607",
    "services relative": "3a12a8a1c76848beccffdbc74ec12220",
    "services quoted": "753abd7835e68aa9e5c267c1150f8e17",
    "services empty": "f4a929afb9d308909ec7e0071d4d3efa",
    "userassist system": "3025d39dd4799074922b8e482d15d775",
    "userassist guid": "e1897ad18b9e3ea0d8cec4725ead6521",
    "userassist programs": "f813bc43d9a221a58058922bcc8b88de",
    "userassist app ID": "4effb427d978a29e8cf56f2287cad767",
    "userassist counter": "9814a6cb1e39a25bb1d634ed34f48bdf",
    "taskcache": "48f946bdf7893bbdfc53c0abd0e63d11",
    "prefetch short": "1223b00a3ad8ce47e1c8b8b0c18fac51",
    "prefetch cut": "32d74e7546abf2a5a14ff947d49abe7f",
    "prefetch cut twice": "cd3d740a1136ed0876fa0c2edfb22e0a",
    "prefetch none": "cb4c6a9d936a2a06247dcc64aa32ecbb",
    "prefetch 28": "e67209941fc92fffc57bf0ce88d1bc26",
    "timeline System": "e3034fbe934d4adb1e2d1f50c131f473",
    "timeline system guid": "275d7a7b8473588e71b8d92eb929ef4c",
    "timeline windows guid": "d733a1f9cf933de4d2f8c43fdc6c193e",
    "timeline x64 guid": "04f82fed144a4c8f52968227c0b03c68",
    "timeline x86 guid": "928b500d8dfd0778c6819f69f3a432ee",
    "timeline app ID": "eec983863fbf308d233e58ef017dcfb4",
    "timeline drive": "833d9257992a64b7da5f2d9a3466880b",
    "autoruns empty image": "20d05c177fce12f83f03b97baa7d2f67",
    "autoruns fragment image": "ea9e9893fb530002458dcf86fc728e97",
    "autoruns image": "5f98ec05981dbd3f0262d96563b06b8f",
    "autoruns script": "9d34f9efeff275a1736b981544a48fac",
    "autoruns no time": "09d81ad5df657b5c2b404fb58e81a866",
    "autoruns variable launch": "72560e0d0b35dd44ef66dfb688c8342f",
    "mft 100-1:Administrator $SI M...": "35cba4581d14321dfe73580187301467",
    "mft 100-1:Administrator $SI .AC.": "79b69741f600f1a8dc95f6bf27398d75",
    "mft 100-1:Administrator $SI ...B": "cf556f6e0434a4833addb4f5b37b73b8",
    "mft 100-1:Administrator $FN M..B": "9c24a482057edb21ab716ecf3103d880",
    "mft 101-1:Public $SI M...": "6180762d6312cb47a898c98325514f28",
    "mft 101-1:Public $SI .AC.": "7aa732ca19c252d467faa5f1661cff14",
    "mft 101-1:Public $SI ...B": "52b2245a8c4030d5908c18105d9e3c93",
    "mft 101-1:Public $FN M..B": "03413a4c8b85c74be6acb85c0d0f3645",
    "mft 102-1:ad_driver.sys $SI M...": "20e18a0c267eb446143e63666c9e1e5e",
    "mft 102-1:ad_driver.sys $SI .AC.": "984231ec3b7c2b098f9c4063855cd6ce",
    "mft 102-1:ad_driver.sys $SI ...B": "dad790d91db6648941360c4cb03ddd1c",
    "mft 102-1:ad_driver.sys $FN M..B": "921a55319fe3f502880b5c5e2de5aacd",
    "suricata http eve|http|2020-09-19T03:21:48.0": "81ef6a71ebe1a40e4eb8a351de3237a5",
    "suricata fileinfo /coreupdater.exe": "f4961f1f5ada48a1a88f9ee55e560925",
    "suricata fileinfo \\\\fs01\\share\\doc.txt": "f45dcb8d01d0fdce08bef3bbd9495456",
    "suricata flow eve|flow|2020-09-19T03:21:47.0": "91a188015152a5a5f5735ee80e1b862e",
    "import files.json 1": "5f0e712fc57f47d886216504c2cb1a9c",
    "import kerberos.json 1": "c93cbcb0f5f0f5dc0c151637ea29502e",
    "import logons.csv 2": "54ec44be153bd61f7fff04de74a16ad1",
    "import logons.csv 3": "a08152551f2cd300b138842de057ffb9",
    "import logons.csv 4": "d80fa4f333aa8190c07003226027aec4",
    "import logons.csv 5": "8d9fa35bdc508aadf253232bb6013561",
    "import logons.csv 6": "b64b844863d23f57e9cb2e792c5b3a1a",
    "import ntlm.json 1": "d5059014e7818815284ae3b981ead240",
}


def test_no_file_key_changes_an_event_id(tmp_path):
    """A mark in a journal names its event by ID, so a file key that changed one would orphan the marks on it. Every
    parser that fills the file fields, and the import with its roles, give the IDs recorded in GOLDEN."""
    assert fx.labeled_ids(tmp_path, new_roles=True) == GOLDEN


# ---------- a capture's URL path is no file key ----------

@pytest.mark.parametrize("path,key", [
    ("/coreupdater.exe", ""), ("/var/tmp/x", ""), (" /coreupdater.exe", ""),
    ("//server/share/x", r"\server\share\x"), (r"\\server\share\x", r"\server\share\x"),
    (r"C:\Users\Public\x.exe", r"\users\public\x.exe"), ("C:/Users/Public/x.exe", r"\users\public\x.exe"),
    (r"\Windows\System32\cmd.exe", r"\windows\system32\cmd.exe"), (r".\Users\a%b%\x", r"\users\a%b%\x"),
])
def test_a_url_path_gets_no_file_key_and_a_windows_path_keeps_it(path, key):
    """Of the 99 keys Szechuan's capture made from URL paths, none matched a file on disk, and one could match a file at a
    volume root. The path stays in file_path, so Same file name still finds the name (test_pivots.py)."""
    assert file_key(path) == key


def test_a_capture_record_keeps_its_url_path_without_a_key(tmp_path):
    http, fileinfo, share, flow = fx.suricata_events(tmp_path)
    assert (fileinfo.file_path, fileinfo.file_key) == ("/coreupdater.exe", "")
    assert (share.file_path, share.file_key) == (r"\\fs01\share\doc.txt", r"\fs01\share\doc.txt")   # a UNC path is a path
    assert (http.file_path, http.file_key, flow.file_key) == ("", "", "")


# ---------- RECmd rows keyed from their paths, per plugin ----------

def test_recmd_plugin_rows_are_keyed_from_their_paths(tmp_path):
    """AppCompatCache, BAM, Run values, Services, and UserAssist name a program in the forms the Szechuan copies hold. Each
    reader's form is asserted, so dropping one fails its own row. A row with no backslash names no file."""
    e = fx.recmd_events(tmp_path)
    got = {name: (ev.file_path, ev.file_key) for name, ev in e.items()}
    assert got["shim SYSVOL"] == (r"SYSVOL\Windows\System32\services.exe", r"\windows\system32\services.exe")   # DC01's volume
    assert got["shim drive"] == (r"C:\Windows\System32\cmd.exe", r"\windows\system32\cmd.exe")
    assert got["shim D drive"] == (r"D:\setup64.exe", r"\setup64.exe")
    assert got["shim packaged"] == ("", "")                                # tab-separated text
    assert got["bam device path"] == (r"\Device\HarddiskVolume3\Windows\explorer.exe", r"\windows\explorer.exe")
    assert got["bam app ID"] == ("", "")
    assert got["run quoted"] == (r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                                 r"\program files\vmware\vmware tools\vmtoolsd.exe")
    assert got["run windir"] == (r"C:\Windows\system32\SecurityHealthSystray.exe", r"\windows\system32\securityhealthsystray.exe")
    assert got["run comspec"] == ("", "")                                 # %COMSPEC% has no folder to write out
    assert got["run appdata"] == (r"%APPDATA%\Sync\sync.exe", "")        # a path, but the profile's folder is not known
    assert got["run key only"] == ("", "")                                # the plugin's row for the key names no value
    # a svchost-hosted service is its ServiceDLL (test_service_dll_key.py); the host shared by many services is not a key
    assert got["services svchost"] == (r"C:\Windows\System32\aelupsvc.dll", r"\windows\system32\aelupsvc.dll")
    assert got["services driver"] == (r"C:\Windows\System32\drivers\ad_driver.sys", r"\windows\system32\drivers\ad_driver.sys")
    assert got["services relative"][1] == r"\windows\system32\drivers\vmmemctl.sys"   # relative to the Windows folder
    assert got["services quoted"][1] == r"\program files\vmware\vmware tools\vmware vgauth\vgauthservice.exe"
    assert got["services empty"] == ("", "")
    assert got["userassist system"] == (r"{System}\NOTEPAD.EXE", r"\windows\system32\notepad.exe")
    assert got["userassist guid"][1] == r"\windows\system32\cscript.exe"
    assert got["userassist programs"] == (r"{Common Programs}\Accessories\Paint.lnk", "")   # per-user: no key, a name
    assert got["userassist app ID"] == ("", "") and got["userassist counter"] == ("", "")
    assert got["taskcache"] == ("", "")                                   # its kind ranks Same task name only
    # What the row was, and when, are untouched: only the file fields are filled
    # A bare program name has no path to key, but it keeps its name, so Same file name reaches it
    from glessner.parsers.recmd import _program
    run_key = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    assert _program("Run", run_key, "ctfmon", "ctfmon.exe", "") == ("ctfmon.exe", "")
    assert _program("Run", run_key, "ctfmon", "ctfmon.exe /x", "") == ("ctfmon.exe", "")
    assert _program("Run", run_key, "x", r"C:\Program Files\x\y.xyz -a", "") == ("", "")   # a folder's fragment is no name
    assert _program("UserAssist", "k", "x", "Microsoft.Windows.Explorer", "") == ("", "")   # an app ID is not a program
    assert e["shim SYSVOL"].registry_value == "AppCompatCache" and e["shim SYSVOL"].artifact == "registry"
    assert e["services svchost"].registry_path == fx.SERVICES and e["run quoted"].registry_data.startswith('"C:')


# ---------- folder variables and \SystemRoot, on the shared key path ----------

@pytest.mark.parametrize("path,key", [
    (r"%SystemRoot%\System32\smss.exe", r"\windows\system32\smss.exe"),
    (r"%systemroot%\System32\smss.exe", r"\windows\system32\smss.exe"),
    (r"\SystemRoot\System32\smss.exe", r"\windows\system32\smss.exe"),
    (r"%windir%\x.dll", r"\windows\x.dll"),
    (r"%ProgramFiles%\a\b.exe", r"\program files\a\b.exe"), (r"%ProgramW6432%\a\b.exe", r"\program files\a\b.exe"),
    (r"%ProgramFiles(x86)%\a\b.exe", r"\program files (x86)\a\b.exe"),
    (r"%CommonProgramFiles%\x.dll", r"\program files\common files\x.dll"),
    (r"%CommonProgramW6432%\x.dll", r"\program files\common files\x.dll"),
    (r"%CommonProgramFiles(x86)%\x.dll", r"\program files (x86)\common files\x.dll"),
    (r"%ProgramData%\x\y.exe", r"\programdata\x\y.exe"), (r"%ALLUSERSPROFILE%\x\y.exe", r"\programdata\x\y.exe"),
    (r"%SystemDrive%\x\y.exe", r"\x\y.exe"),
    (r"%USERPROFILE%\x\y.exe", ""), (r"%APPDATA%\x", ""), (r"%LOCALAPPDATA%\x", ""), (r"%TEMP%\x.exe", ""), (r"%COMSPEC%", ""),
    (r"%SystemRoot%", ""), (r"C:\%windir%\x", r"\%windir%\x"),   # only a leading variable is written out
])
def test_folder_variables_and_systemroot_are_written_out_on_the_shared_key_path(path, key):
    """A user's variables (%USERPROFILE%, %APPDATA%, %LOCALAPPDATA%, %TEMP%) need the profile's folder, which isn't known,
    so a path under one has no key."""
    assert file_key(path) == key


def test_the_command_reducer_takes_every_variable_and_an_unquoted_path_with_a_space():
    assert command_file(r"%ProgramFiles(x86)%\Foo Bar\x.exe -a") == r"C:\Program Files (x86)\Foo Bar\x.exe"
    assert command_file(r"%CommonProgramFiles(x86)%\Foo Bar\x.dll /s") == r"C:\Program Files (x86)\Common Files\Foo Bar\x.dll"
    assert command_file(r"%ProgramData%\x\y.exe -a") == r"C:\ProgramData\x\y.exe"
    assert command_file(r'"%SystemRoot%\System32\svchost.exe" -k netsvcs') == r"C:\Windows\System32\svchost.exe"
    assert command_file(r"%windir%\system32\SecurityHealthSystray.exe") == r"C:\Windows\system32\SecurityHealthSystray.exe"
    assert command_file(r"system32\drivers\x.sys") == r"C:\Windows\system32\drivers\x.sys"
    assert command_file(r"\??\C:\x\y.sys") == r"C:\x\y.sys"
    assert command_file(r"%COMSPEC% /c x.bat") == "%COMSPEC%"                       # no folder to write out: the first word
    assert command_file(r"%USERPROFILE%\Foo Bar\x.exe -q") == r"%USERPROFILE%\Foo Bar\x.exe"   # a path, and no key
    assert file_key(command_file(r"%USERPROFILE%\Foo Bar\x.exe -q")) == ""
    assert expand_folder(r"\x\y") == r"\x\y" and expand_folder(r"%NOPE%\x") == r"%NOPE%\x"
    # An unquoted path with a space and an extension the list lacks, or with none, must not give its first word, a
    # folder's fragment, as a key: .vbs, .js, .jar, and the root-relative form are programs; an unknown extension is no key
    assert command_file(r"C:\Program Files\App\app.vbs") == r"C:\Program Files\App\app.vbs"
    assert command_file(r"%ProgramFiles%\My App\run.js /x") == r"C:\Program Files\My App\run.js"
    assert command_file(r"\Program Files\x\y.exe -a") == r"\Program Files\x\y.exe"
    assert command_file(r"C:\Program Files\Java\bin\javaw.jar -x") == r"C:\Program Files\Java\bin\javaw.jar"
    assert command_file(r"C:\Program Files\x\y.xyz -a") == ""
    assert file_key(command_file(r"C:\Program Files\x\y.xyz -a")) == ""
    assert command_file(r"System32\svchost.exe -k netsvcs") == r"C:\Windows\System32\svchost.exe"   # a whole word ending in .exe
    assert command_file("rundll32.exe x.dll,Run") == "rundll32.exe" and command_file("") == ""


def test_every_command_line_source_writes_the_variables_out(tmp_path):
    """7045 and 4688 (EvtxECmd), RECmd's Run and Services rows, and Autoruns' launch strings all key the same files."""
    evtx = fx.evtx_events(tmp_path)
    assert evtx["7045 SystemRoot"].file_key == r"\windows\system32\drivers\a.sys"
    assert evtx["7045 x86 with a space"].file_key == r"\program files (x86)\foo bar\x.exe"
    assert evtx["4688 SystemRoot"].file_key == r"\windows\system32\smss.exe"        # the process, \SystemRoot written out
    recmd = fx.recmd_events(tmp_path)
    assert recmd["run windir"].file_key == r"\windows\system32\securityhealthsystray.exe"
    assert recmd["services svchost"].file_key == r"\windows\system32\aelupsvc.dll"
    autoruns = fx.autoruns_events(tmp_path)
    for label in ("autoruns empty image", "autoruns fragment image"):
        # An image path with no file (empty, or "File not found: cmd.exe /c x") is keyed from the launch string, shown as the
        # process; the time description, and with it the ID, still follows the image path
        assert autoruns[label].file_key == r"\programdata\x\y.exe" and autoruns[label].file_path == ""
        assert autoruns[label].process_executable == r"C:\ProgramData\x\y.exe"
        assert autoruns[label].ts_desc == "Image file last written"
    assert autoruns["autoruns variable launch"].file_key == r"\program files (x86)\foo bar\z.exe"
    image = autoruns["autoruns image"]
    assert image.file_key == r"\windows\system32\coreupdater.exe" and not image.process_executable
    assert autoruns["autoruns script"].process_executable == ""   # a script host's launch string names no program to key


# ---------- known folders ----------

def test_known_folders_are_mapped_for_the_timeline_and_userassist(tmp_path):
    """WxTCmd writes System\\cmd.exe or {GUID}\\cmd.exe and RECmd's UserAssist {System}\\cmd.exe. The GUIDs are KNOWNFOLDERID's,
    checked against the Windows SDK's constants as pywin32 carries them."""
    t = fx.wxtcmd_events(tmp_path)
    assert t["timeline System"].file_key == t["timeline system guid"].file_key == r"\windows\system32\cmd.exe"
    assert t["timeline windows guid"].file_key == r"\windows\explorer.exe"
    assert t["timeline x64 guid"].file_key == r"\program files\vendor\app.exe"
    assert t["timeline x86 guid"].file_key == r"\program files (x86)\vendor\app.exe"
    assert t["timeline drive"].file_key == r"\windows\system32\notepad.exe"
    assert t["timeline app ID"].file_key == "" and t["timeline System"].process_executable == r"System\cmd.exe"   # as written
    assert known_folder(r"{SystemX86}\x.exe") == r"C:\Windows\SysWOW64\x.exe"   # on 32-bit Windows it misses, never mis-joins
    assert known_folder(r"{ProgramFiles}\x.exe") == "" and known_folder(r"{Common Programs}\x.lnk") == ""
    assert known_folder(r"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}\x.exe") == r"C:\Windows\System32\x.exe"   # any letter case
    assert known_folder("Microsoft.Windows.Explorer") == "" and known_folder(r"C:\Windows\x.exe") == ""
    u = fx.recmd_events(tmp_path)
    assert u["userassist system"].file_key == r"\windows\system32\notepad.exe"


# ---------- Prefetch names cut at 29 characters ----------

def test_a_prefetch_name_cut_at_29_characters_matches_by_prefix(tmp_path):
    p = fx.pecmd_events(tmp_path)
    assert len(fx.CUT_NAME) == 29
    assert p["prefetch cut"].file_key == r"\users\public\longnamedinstallerprogram_setup_v2.exe"   # the one entry that starts so
    assert p["prefetch cut"].file_path == rf"{fx.VOLUME}\USERS\PUBLIC\{fx.LONG_NAME}"
    assert p["prefetch cut twice"].file_key == "" and p["prefetch none"].file_key == ""   # two entries, or none, name no path
    assert p["prefetch 28"].file_key == ""                                    # a name that is not 29 long is not cut
    assert p["prefetch short"].file_key == r"\windows\system32\cmd.exe"       # the usual match by ending is as it was
    # A whole name that happens to be 29 characters is not cut: its own entry was looked for first, and a sidecar that starts
    # with it (NAME.EXE.CONFIG) is not the program
    from glessner.parsers.pecmd import _by_prefix
    whole = "ABCDEFGHIJKLMNOPQRSTUVWXY.EXE"
    assert len(whole) == 29
    assert _by_prefix(whole, [rf"{fx.VOLUME}\X\{whole}.CONFIG"]) == whole
    cut = "ABCDEFGHIJKLMNOPQRSTUVWXYZABC"
    assert _by_prefix(cut, [rf"{fx.VOLUME}\X\{cut}DEF.EXE"]) == rf"{fx.VOLUME}\X\{cut}DEF.EXE"   # a cut name still matches


# ---------- imports ----------

def test_split_account_reads_the_forms_a_log_writes():
    assert split_account(r"C137\bob") == ("C137", "bob") and split_account("alice@C137.LOCAL") == ("C137.LOCAL", "alice")
    assert split_account("mortysmith/C137.LOCAL") == ("C137.LOCAL", "mortysmith")
    assert split_account("a@b@corp.example") == ("corp.example", "a@b")     # at the last @
    assert split_account("x/y/CORP.EXAMPLE") == ("CORP.EXAMPLE", "x/y")
    assert split_account("alice") == ("", "alice") and split_account(r"\alice") == ("", "alice")
    assert split_account("alice@") == ("", "alice@") and split_account("@corp") == ("", "@corp")
    assert split_account("a/b c") == ("", "a/b c")                             # not a realm
    assert split_account(r"C137\a/b") == ("C137", "a/b")                       # the backslash wins
    # A placeholder, a Unix principal, an address, and a host name are no realm: the realm is dotted and not an address
    assert split_account("N/A") == ("", "N/A") and split_account("root/admin") == ("", "root/admin")
    assert split_account("alice@10.0.0.5") == ("", "alice@10.0.0.5") and split_account("alice@web01") == ("", "alice@web01")
    assert split_account("Administrator/C137.LOCAL") == ("C137.LOCAL", "Administrator")


def test_an_import_keys_windows_paths_and_splits_realm_accounts(tmp_path):
    case, _ = fx.import_case(tmp_path, new_roles=True)
    con, _, _ = open_case(case)
    cols = "source_file, source_record, user_domain, user_name, logon_id, logon_type, file_path, process_executable, file_key"
    rows = {(r[0].rsplit("/", 1)[-1], r[1]): r[2:] for r in con.execute(
        f"SELECT {cols} FROM events WHERE tool = 'import'").fetchall()}
    assert rows["logons.csv", "2"] == ("C137.LOCAL", "alice", "0x3e7", "3", r"C:\Users\Public\x.exe", r"C:\Tools\y.exe",
                                       r"\users\public\x.exe")             # the path role, name@realm split
    assert rows["logons.csv", "3"] == ("C137", "bob", "", "", "", r"C:\Tools\z.exe", r"\tools\z.exe")   # 0x0 is none; the process
    # A path that isn't Windows-form is no key, and does not fall back to the process: the row would name one file and match
    # another
    assert rows["logons.csv", "4"] == ("C137.LOCAL", "Administrator", "0x51a", "10", "/var/tmp/x", r"C:\Tools\y.exe", "")
    assert rows["logons.csv", "5"][2:] == ("", "2", r"\\fs01\share\doc.txt", "sshd", r"\fs01\share\doc.txt")
    assert rows["logons.csv", "6"][-1] == ""                               # a Unix process is no key
    # Zeek: krb's client user/REALM is split, ntlm gets its domain, and files.log's filename is the path
    assert rows["kerberos.json", "1"][:2] == ("C137.LOCAL", "mortysmith")
    assert rows["ntlm.json", "1"][:2] == ("C137", "mortysmith")
    assert rows["files.json", "1"][-3:] == (r"C:\Users\Public\x.exe", "", r"\users\public\x.exe")
    # Same file reaches an MFT record of the file
    mft = fx.mft_events(tmp_path, "FIXTURE", [(r".\Users\Public", "x.exe")])
    load(case.db_path, mft, host="FIXTURE", tool="mftecmd", tool_version="t", run_id="mft", replaces_sources=[],
         staging_dir=case.folder)
    con, _, _ = open_case(case)
    from_import = con.execute("SELECT event_uid FROM events WHERE tool = 'import' AND source_record = '2' "
                              "AND source_file LIKE '%logons.csv'").fetchone()[0]
    found = related(con, from_import, "file")
    assert found["total"] == 6   # itself, files.json's record, and the four events of the MFT record
    artifact = lambda uid: con.execute("SELECT artifact FROM events WHERE event_uid = ?", [uid]).fetchone()[0]
    assert {artifact(e["uid"]) for e in found["events"]} == {"csv_fixture", "zeek", "mft"}


def test_an_old_saved_mapping_still_loads_and_a_new_one_keeps_its_logon_roles():
    old = {"format": "csv", "delimiter": ",", "header": True, "artifact": "csv_fixture",
           "time": {"columns": ["Time"], "format": "ymd", "zone": "UTC"}, "fields": {"user": "User", "path": "Path"},
           "host": {"from": "folder"}, "message": "", "ignore": []}
    assert normalize_mapping(old)["fields"] == {"user": "User", "path": "Path"}
    new = normalize_mapping({**old, "fields": {**old["fields"], "logon_id": "LogonId", "logon_type": "LogonType"}})
    assert new["fields"]["logon_id"] == "LogonId" and new["fields"]["logon_type"] == "LogonType"
    with pytest.raises(MappingError):
        normalize_mapping({**old, "fields": {"logon_name": "x"}})
    assert PRESETS["zeek"]["fields"]["domain"] == ["domainname"] and PRESETS["zeek"]["fields"]["path"] == ["filename"]
