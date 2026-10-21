"""Loads the tool registry, detects installed tools, and recommends missing ones.

Registry files live in the app's registry/ folder, one YAML file per tool. Cases never
supply registry files, so an executable path always comes from detection.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from .intake import entry_kind, walk
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
    outputs: tuple[str, ...]
    parser: str | None
    options: tuple[ToolOption, ...] = ()
    notes: str = ""
    # A tool that writes beside what it reads, such as SrumECmd opening SRUDB.dat with the Windows database engine,
    # runs on copies in its run folder. copy_also names more of the host's files it needs, as handles does.
    work_on_copies: bool = False
    copy_also: tuple[str, ...] = ()
    # The .NET major version a framework-dependent build needs, such as 9; 0 for none. A runtime unpacked in the tools
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
    # Start the tool in its run folder rather than its own: SQLECmd and WxTCmd unpack SQLite.Interop.dll into their
    # working folder and can't delete it afterwards.
    run_in_run_folder: bool = False
    # With empty_result: output simply absent means nothing to report, not a failure. The run is ok, with no events and
    # the empty_result as a note, as for WxTCmd on an empty Timeline. Without it, such a run fails with the reason.
    empty_ok: bool = False


@dataclass(frozen=True)
class DetectedTool:
    spec: ToolSpec
    executable: Path
    version: str          # "unknown" when the version check fails
    dotnet_root: str = ""   # the private .NET runtime this tool runs on, if it needs one and one was found
    missing: str = ""       # why it can't run here, such as Npcap not being installed
    rules: str = ""         # the rule set it runs with, such as "ET Open 11310"; "" for none


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
        rules = rules_version(spec, exe)
        if spec.npcap and not npcap_folder():   # its version check would stop on a missing-DLL dialog
            found[spec.id] = DetectedTool(spec, exe, "unknown", missing=NPCAP_MISSING, rules=rules)
            continue
        root = find_dotnet(tools_folder, spec.dotnet) if spec.dotnet else None
        tool = DetectedTool(spec, exe, "", str(root) if root else "")
        found[spec.id] = DetectedTool(spec, exe, read_version(spec, exe, tool_env(tool)), tool.dotnet_root, rules=rules)
    return found


NPCAP_MISSING = "Needs Npcap, from npcap.com; installing it needs administrator rights"


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


def find_dotnet(tools_folder: Path | None, major: int) -> Path | None:
    """A .NET runtime of this major version unpacked in the tools folder or one level down, such as a dotnet-9 folder."""
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


def read_version(spec: ToolSpec, exe: Path, env: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run([str(exe), *spec.version_args], cwd=exe.parent, capture_output=True,
                                text=True, errors="replace", timeout=VERSION_TIMEOUT_S, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    text = _strip_ansi(result.stdout + "\n" + result.stderr)
    match = re.search(spec.version_regex, text, re.MULTILINE)
    return match.group(1) if match else "unknown"


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
            outputs=tuple(data["outputs"]),
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
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"Registry file {source} is missing a field or is malformed: {exc}") from exc
    if spec.input not in INPUT_MODES:
        raise ValueError(f"Registry file {source}: input must be one of {sorted(INPUT_MODES)}")
    return spec


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
