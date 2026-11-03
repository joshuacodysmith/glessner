"""The disk image builders in scripts/ run the Plaso image that plaso_image.sh pins by its digest, never pull an image,
stop with the pull command when the image is missing, mount the folders they're given by absolute path, and read their
helpers and filters from scripts/. No test runs them: they need Docker and a disk image."""

import re
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
BUILDERS = sorted(SCRIPTS.glob("extract_*.sh"))
PINNED = re.compile(r'^PLASO_IMAGE="log2timeline/plaso@sha256:[0-9a-f]{64}"$', re.MULTILINE)


def test_the_plaso_image_is_pinned_by_its_digest():
    assert PINNED.search((SCRIPTS / "plaso_image.sh").read_text(encoding="utf-8"))


def test_a_missing_plaso_image_stops_the_builder_with_the_pull_command():
    text = (SCRIPTS / "plaso_image.sh").read_text(encoding="utf-8")
    guard = text[PINNED.search(text).end():]
    assert 'docker image inspect "$PLASO_IMAGE" >/dev/null 2>&1 || {' in guard
    assert "docker pull $PLASO_IMAGE" in guard
    assert "exit 1" in guard


def test_each_builder_runs_the_pinned_image_and_never_pulls():
    assert [builder.name for builder in BUILDERS] == [
        "extract_app_dbs.sh", "extract_e01.sh", "extract_more.sh", "extract_wide.sh"]
    for builder in BUILDERS:
        text = builder.read_text(encoding="utf-8")
        assert '. "$HERE/plaso_image.sh"' in text, builder.name
        assert "log2timeline/plaso" not in text, f"{builder.name} names the image apart from $PLASO_IMAGE"
        runs = re.findall(r"docker run[^\n]*", text)
        assert runs, builder.name
        assert all("--pull never" in run for run in runs), builder.name



def test_each_builder_mounts_the_folders_it_is_given_by_absolute_path():
    # docker run -v reads a relative host path as a volume name.
    for builder in BUILDERS:
        flags = re.findall(r'cygpath (-\w+) "\$(?:IMG_DIR|DS_DIR)"', builder.read_text(encoding="utf-8"))
        assert flags, builder.name
        assert set(flags) == {"-am"}, builder.name


def test_each_file_a_builder_runs_in_the_container_is_in_scripts():
    for builder in BUILDERS:
        names = re.findall(r"/scripts/([\w.]+)", builder.read_text(encoding="utf-8"))
        missing = [name for name in names if not (SCRIPTS / name).is_file()]
        assert names, builder.name
        assert not missing, f"{builder.name} reads {missing} from /scripts"
