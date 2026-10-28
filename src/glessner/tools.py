"""Loads the tool registry, detects installed tools, and recommends missing ones.

Registry files live in the app's registry/ folder, one YAML file per tool. Cases never
supply registry files, so an executable path always comes from detection.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import yaml

from .intake import entry_kind, walk, walk_evidence
from .long_paths import long_path
from .version import build_id

REGISTRY_DIR = Path(__file__).resolve().parents[2] / "registry"
VERSION_TIMEOUT_S = 20
INPUT_MODES = {"host_dir", "each_file"}


@dataclass(frozen=True)
class ToolOption:
    id: str
    label: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    publisher: str
    license: str
    download_url: str
    executables: tuple[str, ...]
    version_args: tuple[str, ...]
    version_regex: str
    handles: tuple[str, ...]
    input: str
    args: tuple[str, ...]
    timeout_minutes: int
    # The files a run must write, as name patterns in its output folder. An entry that is a tuple of patterns is a group,
    # of which the run must write at least one: SBECmd's builds name the record of a run differently. The run's other
    # files, such as the console log that 2026.10 builds write for every tool, are hashed with it but not required;
    # SBECmd's own console log can meet its group.
    outputs: tuple[str | tuple[str, ...], ...]
    parser: str | None
    options: tuple[ToolOption, ...] = ()
    notes: str = ""
    # A tool that writes beside what it reads, such as SrumECmd opening SRUDB.dat with the Windows database engine,
    # runs on copies in its run folder. copy_also names more of the host's files it needs, as handles does.
    work_on_copies: bool = False
    copy_also: tuple[str, ...] = ()
    # The .NET major version a framework-dependent build needs, such as 10; 0 for none. A runtime unpacked in the tools
    # folder is used through DOTNET_ROOT, so nothing need be installed machine-wide.
    dotnet: int = 0
    # Why a run that loads nothing has failed, for a tool that can finish quietly without reading its inputs.
    empty_result: str = ""
    # Part of the app, run with the app's own Python, such as the Windows event XML reader; nothing to download.
    builtin: bool = False
    # Needs Npcap's wpcap.dll, as Suricata does even to read capture files. Npcap keeps it in System32\Npcap, which
    # the tool's PATH gets; installing Npcap needs administrator rights, so the app only checks for it.
    npcap: bool = False
    # A rule set beside the executable, such as Suricata's rules\suricata.rules: its file and version file, relative to
    # the executable's folder, and the arguments that load it, with {rules_file}. Without the file the tool runs
    # without them.
    rules: dict | None = None
    # Files of another artifact on the same host that the tool reads too, with the arguments that pass them, using
    # {related}: MFTECmd reading $J takes its volume's $MFT, the one in the nearest folder above the $J, with -m to give
    # each change its folder. Without one the arguments are left out, and the run notes it.
    related: tuple[dict, ...] = ()
    # Start the tool in its run folder rather than its own, so that nothing it writes to its working folder, such as a
    # native library it unpacks and can't delete afterwards, lands in the tool's folder, which a pin covers.
    run_in_run_folder: bool = False
    # With empty_result: output simply absent means nothing to report, not a failure. The run is ok, with no events and
    # the empty_result as a note, as for WxTCmd on an empty Timeline. Without it, such a run fails with the reason.
    empty_ok: bool = False
    # The name patterns a host_dir tool reads in the host's folder, such as LECmd's *.lnk. Intake identifies a file by its
    # signature, so one named otherwise is an input the tool never opens, and the run notes the files it left out.
    selects: tuple[str, ...] = ()
    # Arguments a tool takes when a planned input has none of an artifact beside it, as `related` names files beside an
    # input: SBECmd takes --nl when a hive has no transaction log (registry_log) beside it, a file in its folder named
    # for it with .log in its extension. The run notes it. Without the arguments the tool reads those files, and the
    # run's evidence check covers them.
    without_related: tuple[dict, ...] = ()
    # Files and folders in the tool's own folder that it reads though no argument names them, such as Hayabusa's rules
    # and config folders. A run records their SHA-256 (tool_files).
    tool_files: tuple[str, ...] = ()
    # How the rule or map set the tool runs with is named (rules_label): "kind" is one of LABEL_KINDS, "path" the file or
    # folder it reads, relative to the executable's folder, and "text" the label, with {value} for what it read. Without
    # one, the set is named by the rules block's version file, as Suricata's is.
    rules_label: dict | None = None


@dataclass(frozen=True)
class DetectedTool:
    spec: ToolSpec
    executable: Path
    version: str          # "unknown" when the version check fails
    dotnet_root: str = ""   # the private .NET runtime this tool runs on, if it needs one and one was found
    missing: str = ""       # why it can't run here, such as Npcap not being installed
    rules: str = ""         # the rule or map set it runs with (rules_label), such as "ET Open 11310"; "" for none


@dataclass(frozen=True)
class Recommendation:
    spec: ToolSpec
    artifacts: tuple[str, ...]   # identified artifact types in the case that this tool handles


def load_registry(folder: Path = REGISTRY_DIR) -> dict[str, ToolSpec]:
    specs = {}
    for path in sorted(folder.glob("*.yaml")):
        spec = _parse_spec(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
        specs[spec.id] = spec
    return specs


def detect(specs: Iterable[ToolSpec], tools_folder: Path | None) -> dict[str, DetectedTool]:
    """Find each tool in the tools folder (recursively), then on PATH, and read its version."""
    found = {}
    candidates = _executables_under(tools_folder) if tools_folder and tools_folder.is_dir() else []
    for spec in specs:
        if spec.builtin:   # the app's own Python runs it; its version is the app's build
            found[spec.id] = DetectedTool(spec, Path(sys.executable), build_id())
            continue
        exe = _match(spec, candidates) or _on_path(spec)
        if exe is None:
            continue
        rules = rules_label(spec, exe)
        if spec.npcap and not npcap_folder():   # its version check would stop on a missing-DLL dialog
            found[spec.id] = DetectedTool(spec, exe, "unknown", missing=NPCAP_MISSING, rules=rules)
            continue
        root = find_dotnet(tools_folder, spec.dotnet) if spec.dotnet else None
        tool = DetectedTool(spec, exe, "", str(root) if root else "")
        check = check_version(spec, exe, tool_env(tool))
        # A framework-dependent build that finds no runtime of its major version is stopped by the .NET host, with an
        # exit code and a message of the host's own. A check that ended otherwise, such as by timing out or being blocked,
        # shows the tool lacks nothing, and a build that prints its version has started, on a runtime of the machine.
        absent = dotnet_missing(spec.dotnet) if spec.dotnet and not root and check.host_stopped else ""
        found[spec.id] = DetectedTool(spec, exe, check.version, tool.dotnet_root, missing=absent, rules=rules)
    return found


NPCAP_MISSING = "Needs Npcap, from npcap.com; installing it needs administrator rights"


def dotnet_missing(major: int) -> str:
    """Why a tool that needs a .NET runtime of this major version can't run here, as DetectedTool.missing words it."""
    return f"Needs a .NET {major} runtime: unpack Microsoft's .NET {major} runtime zip into a folder in the tools folder"


def npcap_folder() -> Path | None:
    """Npcap's own folder, where it keeps wpcap.dll, or None when Npcap isn't installed."""
    folder = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "Npcap"
    return folder if (folder / "wpcap.dll").is_file() else None


def rules_file(spec: ToolSpec, exe: Path) -> Path | None:
    if not spec.rules:
        return None
    path = exe.parent / spec.rules["file"]
    return path if path.is_file() else None


def rules_version(spec: ToolSpec, exe: Path) -> str:
    """The rule set a tool runs with, from the version file beside its rules; "" when it has none."""
    if rules_file(spec, exe) is None:
        return ""
    version = exe.parent / spec.rules.get("version_file", "")
    if version.is_file():
        return version.read_text(encoding="utf-8", errors="replace").strip()[:80] or "rules"
    return "rules"


LABEL_KINDS = ("git", "count", "version_line")   # the kinds of ToolSpec.rules_label
GIT = ".git"   # a git checkout's own folder
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")   # a commit's ID, by SHA-1 or SHA-256
VERSION_LINE = re.compile(r"^Version:\s*(\S+)", re.MULTILINE)


def rules_label(spec: ToolSpec, exe: Path, hashes: dict[str, str] | None = None) -> str:
    """The rule or map set a tool runs with, named by its registry entry's rules_label from what its folder holds now,
    or "" when the file or folder the label reads isn't there. By kind:

    - git: the first 7 hex digits of the commit a rules folder's checkout is at (git_commit), then the first 8 of the
      folder's SHA-256 (folder_sha256), as in "fffbdd1, files 7c30c465", so a checkout whose files were edited since
      its commit reads differently from one whose files weren't. The hash is taken from `hashes`, a run's tool_files,
      when they hold it, and computed here otherwise. A rules folder without a readable checkout, such as one unpacked
      from a release zip, gives the folder's 8 digits alone.
    - count: how many files in a folder fit a name pattern, such as Maps\\*.map.
    - version_line: the value of a file's first "Version:" line.

    A tool without a rules_label, such as Suricata, is named by its rules block's version file (rules_version)."""
    label = spec.rules_label
    if not label:
        return rules_version(spec, exe)
    path = exe.parent / label["path"]
    if label["kind"] == "git":
        commit, files = git_commit(path)[:7], _folder_hash(path, exe.parent, hashes)[:8]
        value = f"{commit}, files {files}" if commit and files else commit or files
    elif label["kind"] == "count":
        value = f"{sum(p.is_file() for p in path.parent.glob(path.name)):,}" if path.parent.is_dir() else ""
    elif label["kind"] == "version_line":
        value = _version_line(path)
    else:
        raise ValueError(f"{spec.id}'s rules_label has kind {label['kind']!r}, not one of {list(LABEL_KINDS)}")
    return label["text"].replace("{value}", value) if value else ""


def git_commit(folder: Path) -> str:
    """The commit a git checkout is at, read from the files of its .git folder rather than by running git, since a
    checkout's own config can make git run commands: HEAD, then the file of the branch HEAD names or, for a branch git
    has packed, its line in packed-refs. "" when there is no checkout or no commit can be read."""
    git = folder / GIT
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head if COMMIT.fullmatch(head) else ""   # a detached HEAD holds the commit itself
        ref = head.removeprefix("ref: ").strip()
        if not _ref_in_git(ref):
            return ""
        branch = git / ref
        commit = branch.read_text(encoding="utf-8").strip() if branch.is_file() else _packed_commit(git, ref)
    except (OSError, UnicodeDecodeError):
        return ""
    return commit if COMMIT.fullmatch(commit) else ""


def _ref_in_git(ref: str) -> bool:
    """Whether a branch HEAD names, such as refs/heads/main, reads as a path inside .git: under refs/, with no empty
    part and none that starts with a dot, such as .., and no backslash or colon, which Windows reads as a separator, a
    drive, or a stream. git refuses each of these in a branch's name."""
    parts = ref.split("/")
    return (len(parts) > 1 and parts[0] == "refs" and "\\" not in ref and ":" not in ref
            and all(part and not part.startswith(".") for part in parts))


def _packed_commit(git: Path, ref: str) -> str:
    """A branch's commit in packed-refs, whose lines are "<commit> <ref>", or "" when it has none."""
    for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
        commit, _, name = line.partition(" ")
        if name == ref:
            return commit
    return ""


def _folder_hash(folder: Path, tool_folder: Path, hashes: dict[str, str] | None) -> str:
    """A folder's SHA-256 as a run's tool_files hold it, when they do, or as hashed now; "" for no folder, or one that
    can't be read."""
    key = in_folder(folder, tool_folder)
    if hashes is not None and f"{key}/" in hashes:
        return hashes[f"{key}/"]
    try:
        return folder_sha256(folder) if folder.is_dir() else ""
    except OSError:
        return ""


def _version_line(path: Path) -> str:
    try:
        match = VERSION_LINE.search(path.read_text(encoding="utf-8-sig", errors="replace"))
    except OSError:
        return ""
    return match.group(1) if match else ""


class ToolListing(NamedTuple):
    """The files of a tool that a run records or a pin keeps: `hashes` is tool_files' value, and `folders` has the
    listing (folder_listing) of each folder in it, by the folder's key there, such as "Maps/"."""
    hashes: dict[str, str]
    folders: dict[str, dict[str, str]]


def tool_files(tool: DetectedTool, argv: list[str], links: list[str] | None = None) -> dict[str, str]:
    """The SHA-256 of the files in the tool's own folder that a run of it names (tool_listing's `hashes`)."""
    return tool_listing(tool, argv, links).hashes


def tool_listing(tool: DetectedTool, argv: list[str], links: list[str] | None = None) -> ToolListing:
    """The SHA-256 of the files in the tool's own folder that a run of it names, by their paths there with forward
    slashes, in path order, and the files of each folder among them. The files are the executable; each .dll beside it,
    whatever the case of the extension, which a .NET build loads, with its runtimeconfig.json and deps.json; each
    argument that names a path in the folder, or whose part after = does; the rules block's version file; and the
    registry's tool_files. A folder is recorded under its path and a /, with the hash of its listing (listing_sha256),
    which skips the links in it; each is added to `links` as "path -> target", its path in the tool's folder. A path
    that doesn't exist is left out. A builtin tool, which the app's own Python runs, has none. OSError when a file can't
    be read or a folder can't be listed."""
    if tool.spec.builtin:
        return ToolListing({}, {})
    exe, spec = tool.executable, tool.spec
    named = [exe, *_libraries(exe), *_argument_paths(argv), *(exe.parent / rel for rel in spec.tool_files)]
    if spec.rules and spec.rules.get("version_file"):
        named.append(exe.parent / spec.rules["version_file"])
    hashes, folders = {}, {}
    for path in named:
        if not (rel := in_folder(path, exe.parent)):
            continue
        if path.is_dir():
            skipped: list[str] = []
            folders[f"{rel}/"] = folder_listing(path, skipped)
            hashes[f"{rel}/"] = listing_sha256(folders[f"{rel}/"])
            if links is not None:
                links += (f"{rel}/{link}" for link in skipped)
        elif path.is_file():
            hashes[rel] = file_sha256(path)
    return ToolListing(dict(sorted(hashes.items())), dict(sorted(folders.items())))


def pin_files(tool: DetectedTool, links: list[str] | None = None) -> ToolListing:
    """What a run of the tool would record (tool_listing), for a command line made of the registry's arguments with the
    tool's folder and its rules file filled in and no evidence or output folder, which a pin doesn't have. An argument
    that holds another placeholder, such as {host_dir} or an option's {value}, names no file in the tool's folder."""
    spec, exe = tool.spec, tool.executable
    values = {"{tool_dir}": str(exe.parent)}
    args = list(spec.args)
    if (rules := rules_file(spec, exe)) is not None:
        values["{rules_file}"] = str(rules)
        args += spec.rules.get("args", [])
    for key, value in values.items():
        args = [arg.replace(key, value) for arg in args]
    return tool_listing(tool, [str(exe), *args], links)


def _libraries(exe: Path) -> list[Path]:
    """What a .NET tool loads from its own folder: each .dll beside the executable, whatever the case of its extension,
    and the executable's runtimeconfig.json and deps.json. Nothing for a folder that isn't there."""
    try:
        beside = sorted(p for p in exe.parent.iterdir() if p.suffix.lower() == ".dll")
    except (FileNotFoundError, NotADirectoryError):
        return []
    return [*beside, exe.with_name(f"{exe.stem}.runtimeconfig.json"), exe.with_name(f"{exe.stem}.deps.json")]


def _argument_paths(argv: list[str]) -> list[Path]:
    """The absolute paths a command line names: each argument that is one, or whose part after = is one, as in
    --set classification-file=<path>."""
    texts = [text for arg in argv for text in (arg, arg.partition("=")[2])]
    return [Path(text) for text in texts if text and Path(text).is_absolute()]


def in_folder(path: Path, folder: Path) -> str:
    """`path`'s path in `folder`, with forward slashes, or "" when it isn't in it. Both are read with any .. resolved,
    and no link followed."""
    path, folder = Path(os.path.abspath(path)), Path(os.path.abspath(folder))
    return path.relative_to(folder).as_posix() if path != folder and path.is_relative_to(folder) else ""


def folder_listing(folder: Path, links: list[str] | None = None) -> dict[str, str]:
    """The SHA-256 of each file in a folder and below, by its path in the folder with forward slashes, in code point
    order. A .git folder is left out, and links are skipped, as intake.walk skips them; each link outside .git is added
    to `links` as "path -> target", its path in the folder. OSError when a folder can't be listed or a file can't be
    read."""
    unreadable: list[tuple[str, str]] = []
    found: list[str] = []
    paths = sorted(rel for rel in walk_evidence(folder, found, unreadable) if GIT not in rel.split("/"))
    for rel, error in unreadable:
        if GIT not in rel.split("/"):
            raise OSError(f"{folder / rel} can't be listed: {error}")
    if links is not None:
        links += (link for link in found if GIT not in link.partition(" -> ")[0].split("/"))
    root = long_path(folder)
    return {rel: file_sha256(long_path(root, rel)) for rel in paths}


def listing_sha256(listing: dict[str, str]) -> str:
    """The SHA-256 of the UTF-8 text of a "<sha256>  <path>" line for each file of a folder's listing, sorted by path in
    code point order. sha256sum prints the same lines for the same paths in that order, so the value can be checked
    without the app."""
    lines = "".join(f"{digest}  {rel}\n" for rel, digest in sorted(listing.items()))
    return hashlib.sha256(lines.encode("utf-8", errors="surrogatepass")).hexdigest()


def folder_sha256(folder: Path, links: list[str] | None = None) -> str:
    """A folder's SHA-256: that of its listing's lines (listing_sha256). OSError when a folder can't be listed or a file
    can't be read."""
    return listing_sha256(folder_listing(folder, links))


def file_sha256(path: Path) -> str:
    """A file's SHA-256, as lowercase hex. OSError naming the file when it can't be opened or read."""
    with path.open("rb") as f:
        try:
            return hashlib.file_digest(f, "sha256").hexdigest()
        except OSError as exc:   # an error in a read, unlike one in the open, carries no file name
            raise OSError(exc.errno, exc.strerror, str(path)) from exc


def find_dotnet(tools_folder: Path | None, major: int) -> Path | None:
    """A .NET runtime of this major version unpacked in the tools folder or one level down, such as a dotnet-10 folder."""
    if not tools_folder or not tools_folder.is_dir():
        return None
    below = sorted(Path(e.path) for e in os.scandir(tools_folder) if entry_kind(e) == "folder")   # links skipped
    for folder in [tools_folder, *below]:
        shared = folder / "shared" / "Microsoft.NETCore.App"
        if (folder / "dotnet.exe").is_file() and shared.is_dir() and any(shared.glob(f"{major}.*")):
            return folder
    return None


def tool_env(tool: DetectedTool) -> dict[str, str] | None:
    """The environment a tool runs in: this process's, plus DOTNET_ROOT for a private runtime and Npcap's folder on
    PATH for a tool that needs it. None to inherit."""
    env = {}
    if tool.dotnet_root:
        env.update(DOTNET_ROOT=tool.dotnet_root, DOTNET_ROOT_X64=tool.dotnet_root)
    if tool.spec.npcap and (folder := npcap_folder()):
        env["PATH"] = f"{folder}{os.pathsep}{os.environ.get('PATH', '')}"
    return {**os.environ, **env} if env else None


def recommend(specs: Iterable[ToolSpec], detected: dict[str, DetectedTool], artifacts: set[str]) -> list[Recommendation]:
    """Registry tools that handle an identified artifact type but are not installed."""
    out = []
    for spec in specs:
        wanted = tuple(a for a in spec.handles if a in artifacts)
        if wanted and spec.id not in detected:
            out.append(Recommendation(spec, wanted))
    return out


class VersionCheck(NamedTuple):
    """What running a tool for its version showed: `version`, "unknown" when it printed none, and `host_stopped`, whether
    the .NET host stopped the tool before it started, as it does for a framework-dependent build with no runtime of the
    major version it needs."""
    version: str
    host_stopped: bool


HOST_EXIT_CODES = range(0x80008000, 0x80008100)   # the .NET host's own exit codes, such as 0x80008096 for a framework not found
HOST_MESSAGE = re.compile(r"You must install (?:or update )?\.NET")


def check_version(spec: ToolSpec, exe: Path, env: dict[str, str] | None = None) -> VersionCheck:
    """Run the tool with its version arguments, with a time limit, and read its version from the output by the registry's
    regex. A tool that can't be started, or doesn't finish in time, has no version and wasn't stopped by the host."""
    try:
        result = subprocess.run([str(exe), *spec.version_args], cwd=exe.parent, capture_output=True,
                                text=True, errors="replace", timeout=VERSION_TIMEOUT_S, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return VersionCheck("unknown", False)
    text = _strip_ansi(result.stdout + "\n" + result.stderr)
    match = re.search(spec.version_regex, text, re.MULTILINE)
    if match:
        return VersionCheck(match.group(1), False)
    code = result.returncode & 0xFFFFFFFF   # Windows reports the code unsigned; a signed reading of it is the same code
    return VersionCheck("unknown", code in HOST_EXIT_CODES or bool(HOST_MESSAGE.search(text)))


def _parse_spec(data: dict, source: str) -> ToolSpec:
    try:
        builtin = bool(data.get("builtin", False))
        # A built-in tool has nothing to find or download.
        detect_cfg = {"executables": [], "version": {"args": [], "regex": ""}} if builtin else data["detect"]
        version = detect_cfg["version"]
        spec = ToolSpec(
            id=data["id"],
            name=data["name"],
            publisher=data.get("publisher", ""),
            license=data.get("license", ""),
            download_url="" if builtin else data["download_url"],
            executables=tuple(detect_cfg["executables"]),
            version_args=tuple(version["args"]),
            version_regex=version["regex"],
            handles=tuple(data["handles"]),
            input=data["input"],
            args=tuple(data["run"]["args"]),
            timeout_minutes=int(data["run"].get("timeout_minutes", 30)),
            outputs=_outputs(data["outputs"], source),
            parser=data.get("parser"),
            options=tuple(ToolOption(o["id"], o["label"], tuple(o["args"])) for o in data.get("options") or []),
            notes=data.get("notes") or "",
            work_on_copies=bool(data.get("work_on_copies", False)),
            copy_also=tuple(data.get("copy_also") or ()),
            dotnet=int(data.get("dotnet") or 0),
            empty_result=data.get("empty_result") or "",
            builtin=builtin,
            npcap=bool(data.get("npcap", False)),
            rules=data.get("rules") or None,
            related=tuple(data.get("related") or ()),
            run_in_run_folder=bool(data.get("run_in_run_folder", False)),
            empty_ok=bool(data.get("empty_ok", False)),
            selects=tuple(data.get("selects") or ()),
            without_related=tuple(data.get("without_related") or ()),
            tool_files=tuple(data.get("tool_files") or ()),
            rules_label=data.get("rules_label") or None,
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"Registry file {source} is missing a field or is malformed: {exc}") from exc
    if spec.input not in INPUT_MODES:
        raise ValueError(f"Registry file {source}: input must be one of {sorted(INPUT_MODES)}")
    label = spec.rules_label
    if label is not None and not (isinstance(label, dict) and label.get("kind") in LABEL_KINDS and label.get("path")
                                  and "{value}" in str(label.get("text", ""))):
        raise ValueError(f"Registry file {source}: rules_label needs a kind, one of {list(LABEL_KINDS)}, a path, and "
                         "a text holding {value}")
    return spec


def _outputs(entries: object, source: str) -> tuple[str | tuple[str, ...], ...]:
    """A registry file's outputs: a list whose entries are each a name pattern, or a list of them that is a group (see
    ToolSpec.outputs). ValueError, naming the file, for anything else."""
    def is_pattern(item: object) -> bool:
        return isinstance(item, str) and bool(item)

    def is_group(item: object) -> bool:
        return isinstance(item, list) and bool(item) and all(is_pattern(pattern) for pattern in item)

    if not isinstance(entries, list) or not all(is_pattern(entry) or is_group(entry) for entry in entries):
        raise ValueError(f"Registry file {source}: outputs must be a list of name patterns, each one text or a list of texts")
    return tuple(entry if isinstance(entry, str) else tuple(entry) for entry in entries)


def _executables_under(folder: Path) -> list[Path]:
    """The .exe files in the tools folder and below, in path order. Links aren't followed (intake.walk), so a junction
    can't bring in executables from elsewhere, such as the evidence."""
    return [Path(dirpath) / f for dirpath, filenames in walk(folder) for f in filenames if f.lower().endswith(".exe")]


def _match(spec: ToolSpec, candidates: list[Path]) -> Path | None:
    for pattern in spec.executables:
        for path in candidates:
            if fnmatch.fnmatch(path.name.lower(), pattern.lower()):
                return path
    return None


def _on_path(spec: ToolSpec) -> Path | None:
    for pattern in spec.executables:
        if not any(ch in pattern for ch in "*?["):
            hit = shutil.which(pattern)
            if hit:
                return Path(hit)
    return None


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)
