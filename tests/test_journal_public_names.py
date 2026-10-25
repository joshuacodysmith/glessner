"""The journal's members that other modules call are public: the last-action reader, Journal.started, and
Journal.skipped_lines. overview.py and server.py import no underscore name from journal.py and read no underscore attribute
of the journal module or of a Journal, so a rename inside journal.py can't break either."""

import ast
import json
import random
from pathlib import Path
from types import SimpleNamespace

import pytest
from chain_fixtures import AT, MARKS, UID, add, as_format, chained, note, unchained

from glessner import journal as journal_module
from glessner import overview, server
from glessner.case import create_case, open_case
from glessner.journal import APP_NAMES, Journal, entries

SRC = Path(__file__).resolve().parent.parent / "src" / "glessner"
CALLERS = ("overview.py", "server.py")


def is_private(name: str) -> bool:
    return name.startswith("_") and not (name.startswith("__") and name.endswith("__"))


def names_journal_class(annotation, classes=frozenset({"Journal"})) -> bool:
    """Whether an annotation names the Journal class, under any of the `classes` names: also written as a string, as one
    side of a union, or inside Optional[...] or Union[...]."""
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        annotation = ast.parse(annotation.value, mode="eval").body
    if isinstance(annotation, ast.BinOp):
        return names_journal_class(annotation.left, classes) or names_journal_class(annotation.right, classes)
    if isinstance(annotation, ast.Subscript) and getattr(annotation.value, "id", getattr(annotation.value, "attr", "")) in (
            "Optional", "Union"):
        parts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        return any(names_journal_class(part, classes) for part in parts)
    return (isinstance(annotation, ast.Name) and annotation.id in classes) or (
        isinstance(annotation, ast.Attribute) and annotation.attr in classes)


ATTRIBUTE_CALLS = ("getattr", "hasattr", "setattr", "delattr")


def private_uses(source: str) -> list[str]:
    """What the source takes from journal.py that is private, as written: each underscore name it imports from the module,
    and each underscore attribute it reads, tests, sets, or deletes by name (getattr, hasattr, setattr, delattr, or a key of
    vars() or __dict__) of the module, of the Journal class, or of a Journal. A Journal is a variable or parameter
    annotated Journal (also Optional[Journal], or the class under an alias it imports), a name assigned a Journal(...) or
    another Journal, a name `journal`, or an attribute `.journal`. Only code counts: a docstring or a comment that names
    one is no use. A name built at run time, such as getattr(journal, "_" + "skip"), is beyond a static check."""
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    modules, journals, classes, found = set(), {"journal"}, {"Journal"}, []
    for node in nodes:   # the imports first: they bind the names the rest is read by
        if isinstance(node, ast.ImportFrom):
            if node.module == "glessner.journal" or (node.level == 1 and node.module == "journal"):
                found += [f"imports {a.name}" for a in node.names if is_private(a.name)]
                classes |= {a.asname for a in node.names if a.name == "Journal" and a.asname}
            elif node.module in (None, "glessner"):
                modules |= {a.asname or a.name for a in node.names if a.name == "journal"}
        elif isinstance(node, ast.Import):
            modules |= {a.asname for a in node.names if a.name == "glessner.journal" and a.asname}
    journals |= classes

    def of_journal(node) -> bool:
        if isinstance(node, ast.Name):
            return node.id in modules | journals
        if isinstance(node, ast.NamedExpr):
            return of_journal(node.value)
        if isinstance(node, ast.Call):
            return names_journal_class(node.func, classes)
        return isinstance(node, ast.Attribute) and node.attr in modules | journals

    for node in nodes:
        if isinstance(node, ast.arg | ast.AnnAssign) and node.annotation and names_journal_class(node.annotation, classes):
            journals.add(node.arg if isinstance(node, ast.arg) else getattr(node.target, "id", ""))
    known = None
    while known != len(journals):   # a name assigned from a Journal is one, whatever order the assignments come in
        known = len(journals)
        for node in nodes:
            if isinstance(node, ast.Assign | ast.NamedExpr):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if of_journal(node.value):
                    journals |= {t.id for t in targets if isinstance(t, ast.Name)}

    def private_name(node) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and is_private(node.value)

    def dict_of_journal(node) -> bool:
        """Whether a node is vars(x) or x.__dict__ of a Journal or the module."""
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "vars"
                and len(node.args) == 1 and of_journal(node.args[0])) or (
            isinstance(node, ast.Attribute) and node.attr == "__dict__" and of_journal(node.value))

    def private_read(node) -> bool:
        if isinstance(node, ast.Attribute):
            return is_private(node.attr) and of_journal(node.value)
        if isinstance(node, ast.Subscript):
            return dict_of_journal(node.value) and private_name(node.slice)
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ATTRIBUTE_CALLS
                and len(node.args) > 1 and of_journal(node.args[0]) and private_name(node.args[1]))

    found += [f"reads {ast.unparse(node)}" for node in nodes if private_read(node)]
    return found


@pytest.mark.parametrize("name", CALLERS)
def test_a_caller_of_the_journal_takes_no_private_name_from_it(name):
    assert private_uses((SRC / name).read_text(encoding="utf-8")) == []


def test_the_check_for_private_names_finds_each_way_to_reach_one_and_ignores_prose():
    """The check above must not pass for want of looking: each way of reaching a private member is found, and a docstring, a
    public name, another object's underscore attribute, and a dunder are not."""
    found = {
        "from .journal import _chained": ["imports _chained"],
        "from glessner.journal import REPLAY_ERRORS, _read": ["imports _read"],
        "def f(journal):\n    return journal._started()": ["reads journal._started"],
        "def f(app):\n    return app.journal._skip": ["reads app.journal._skip"],
        "from . import journal as jm\n\ndef f():\n    return jm._read": ["reads jm._read"],
        "import glessner.journal as jm\n\ndef f():\n    return jm._read": ["reads jm._read"],
        "def f(j: Journal):\n    return j._skip": ["reads j._skip"],
        "def f(j: 'Journal | None'):\n    return j._skip": ["reads j._skip"],
        "def f(case):\n    j = Journal(case)\n    return j._started()": ["reads j._started"],
        "def f():\n    return Journal._started": ["reads Journal._started"],
        "def f(journal):\n    return getattr(journal, '_skip')": ["reads getattr(journal, '_skip')"],
        # A Journal held under another name, or reached another way
        "def f(app):\n    j = app.journal\n    return j._skip": ["reads j._skip"],
        "def f(app):\n    k = j\n    j = app.journal\n    return k._skip": ["reads k._skip"],
        "def f(app):\n    return (j := app.journal)._skip": ["reads (j := app.journal)._skip"],
        "from .journal import Journal as J\n\ndef f(j: J):\n    return j._skip": ["reads j._skip"],
        "from .journal import Journal as J\n\ndef f(case):\n    return J(case)._skip": ["reads J(case)._skip"],
        "def f(j: Optional[Journal]):\n    return j._skip": ["reads j._skip"],
        "def f(j: typing.Union[Journal, None]):\n    return j._skip": ["reads j._skip"],
        "def f(journal):\n    return hasattr(journal, '_skip')": ["reads hasattr(journal, '_skip')"],
        "def f(journal):\n    setattr(journal, '_skip', set())": ["reads setattr(journal, '_skip', set())"],
        "def f(journal):\n    delattr(journal, '_skip')": ["reads delattr(journal, '_skip')"],
        "def f(journal):\n    return vars(journal)['_skip']": ["reads vars(journal)['_skip']"],
        "def f(journal):\n    return journal.__dict__['_skip']": ["reads journal.__dict__['_skip']"],
    }
    for source, expected in found.items():
        assert private_uses(source) == expected, source
    quiet = [
        'def f(journal):\n    """Calls journal._started() and Journal._skip."""\n    return journal.started()',
        "from .journal import Journal, last_action",
        "def f(other):\n    return other._private",
        "def f(journal):\n    return journal.__class__",
        "def f(journal):\n    # journal._started() is private\n    return journal.skipped_lines",
        "def f(app):\n    j = app.cache\n    return j._skip",
        "def f(j: Optional[Other]):\n    return j._skip",
        "def f(journal):\n    return hasattr(journal, 'started') and vars(journal)['path']",
    ]
    for source in quiet:
        assert private_uses(source) == [], source


@pytest.fixture
def case(tmp_path):
    """A case at format 2 with an empty journal and no head record, for a test that writes its own journal."""
    (tmp_path / "evidence" / "DC01").mkdir(parents=True)
    made = create_case(tmp_path / "case", "Test", tmp_path / "evidence", "cody")
    as_format(made.folder, 2)
    return open_case(made.folder)


def given_last(path: Path):
    """The newest entry the shared reader gives that someone made, or None."""
    return next((e for e in reversed(entries(path)) if not (isinstance(e["who"], str) and e["who"] in APP_NAMES)), None)


def test_the_overview_reads_the_last_action_with_the_journal_s_public_reader():
    assert callable(journal_module.last_action)
    assert overview._last_action is journal_module.last_action


def test_the_last_action_is_the_newest_entry_by_someone_that_the_shared_reader_gives(tmp_path):
    """The public reader gives what entries() gives for a chained journal, one with only the app's entries, an empty one, and
    a format 2 line under the seal whose who is a list or an object, which is someone's, as written, and a journal that ends
    in a line holding 0x00 or in a torn line, with a chain or without one. A chained line whose who is a list isn't given
    by the shared reader, so it isn't the last action either."""
    hostile = add(chained([MARKS[1]]), "note", who=["ann"], target=UID, text="not given")
    cases = {
        "chained": chained([MARKS[1]]),
        "only the app's": chained([]),
        "empty": b"",
        "a list who under the seal": chained([], before=unchained({**note(1), "who": ["cody", "ann"]})),
        "an object who under the seal": chained([], before=unchained({**note(1), "who": {"by": "cody"}})),
        "a list who in a chained line": hostile,
        # A last line holding 0x00, or a torn one, is a write in progress: it gives nothing, and the note before it is the answer
        "a long line with 0x00 after the chain": chained([], before=unchained(note(1))) + b"z" * 150 + b"\x00\n",
        "a torn line after the chain": chained([], before=unchained(note(1))) + b'{"seq":',
        # With no chain, format 2's parse reads UTF-16 JSON too, so only the rule for a last line holding 0x00 keeps it out
        "UTF-16 JSON as the last line of an unchained journal": (
            unchained(note(1)) + json.dumps(note(2)).encode("utf-16-le") + b"\n"),
    }
    for n, (name, data) in enumerate(cases.items()):
        path = tmp_path / f"{n}.jsonl"
        path.write_bytes(data)
        assert journal_module.last_action(path) == given_last(path), name
    path = tmp_path / "list.jsonl"
    path.write_bytes(cases["a list who under the seal"])
    assert journal_module.last_action(path)["who"] == ["cody", "ann"]
    path.write_bytes(cases["a list who in a chained line"])
    assert journal_module.last_action(path)["text"] == "first look"


def test_started_says_whether_the_journal_has_a_chain_and_the_private_name_is_gone(case):
    path = case.folder / "journal.jsonl"
    path.write_bytes(unchained(note(1)))
    journal = Journal(case)
    assert journal.started() is False
    path.unlink()
    assert journal.started() is False   # a journal deleted while the case is open has no chain to continue
    path.write_bytes(chained([MARKS[0]]))
    assert Journal(case).started() is True
    assert not hasattr(Journal, "_started")


def test_the_lines_the_state_left_out_are_a_read_only_view_the_server_keys_its_trail_on(case):
    """Journal.skipped_lines is a frozen copy of the lines replay couldn't apply, and the server's trail key holds it."""
    damaged = {"seq": 2, "at": AT, "who": "cody", "action": "note", "target": UID}   # no text
    (case.folder / "journal.jsonl").write_bytes(chained([MARKS[0]], before=unchained(note(1), damaged)))
    journal = Journal(case)
    assert journal.skipped_lines == {2} and isinstance(journal.skipped_lines, frozenset)
    assert server._trail_key(SimpleNamespace(journal=journal))[2] == frozenset({2})


NEW_ID = "f" * 32
REKEY = {"at": AT, "who": "glessner", "action": "case_upgrade", "from_format": 1, "to_format": 2, "text": "x",
         "rekey": {"pairs": {UID: NEW_ID}}}
ODD_WHO = [None, 3, "", "glessner", "triage-workbench", ["ann"], {"by": "cody"}, True]
APPENDS = {
    "a note": lambda data, rng: add(data, "note", target=UID, text="later"),
    "an app entry": lambda data, rng: add(data, "build", who="glessner", build="b"),
    "a renamed app's entry": lambda data, rng: add(data, "build", who="triage-workbench", build="b"),
    "a long app entry": lambda data, rng: add(data, "build", who="glessner", build="b" * 30_000),
    "a rekey of format 1": lambda data, rng: add(data, "case_upgrade", who="glessner", from_format=1, to_format=2, text="x",
                                                 rekey={"pairs": {UID: NEW_ID}}),
    "a rekey of format 4": lambda data, rng: add(data, "case_upgrade", who="glessner", from_format=4, to_format=5, text="x",
                                                 rekey={"pairs": {UID: NEW_ID}}),
    "a note of a list who": lambda data, rng: add(data, "note", who=["ann"], target=UID, text="not given"),
    "a blank line": lambda data, rng: data + b"\n",
    "a loose line": lambda data, rng: data + unchained(note(99, text="loose")),
    "a line naming a wrong prev": lambda data, rng: data + b'{"seq": 5, "prev": "bad", "who": "cody"}\n',
    "a line that is no object": lambda data, rng: data + rng.choice([b"[1]\n", b'"x"\n', b"null\n", b"{not json\n"]),
}
UTF16_NOTE = json.dumps(note(9)).encode("utf-16-le") + b"\n"
TAILS = [b"", b"", b'{"seq":', b"x\x00y", b"x\x00y\n", '{"a"'.encode("utf-16"), b"z" * 150 + b"\x00\n", UTF16_NOTE]
UNCHAINED_APPENDS = ("a blank line", "a loose line")   # a line that is no object makes format 2's reader raise


def random_journal(rng: random.Random) -> bytes:
    """A journal of a random shape: format 2 lines of notes, a rekey, and a note of an odd who, under a seal or a
    case_created, then up to four lines of the kinds in APPENDS, and a torn, 0x00, or UTF-16 tail. Some have only the app's
    entries, some have over 64 KiB of them after the newest entry by someone, and some have no chain at all: notes and a
    few loose lines."""
    if rng.random() < 0.15:
        data = unchained(*[note(i + 1, text=f"n{i}") for i in range(rng.randint(0, 3))])
        for _ in range(rng.randint(0, 2)):
            data = APPENDS[rng.choice(UNCHAINED_APPENDS)](data, rng)
        return data + rng.choice(TAILS)
    only_the_app = rng.random() < 0.15   # no entry by someone, so the reader gives None
    before = [] if only_the_app else [note(i + 1, text=f"n{i}") for i in range(rng.randint(0, 3))]
    if rng.random() < 0.3:
        before.append({**REKEY, "seq": len(before) + 1})
    if rng.random() < 0.3:
        before.append({**note(len(before) + 1), "who": rng.choice(ODD_WHO)})
    data = chained([] if only_the_app else rng.sample(MARKS, rng.randint(0, len(MARKS))),
                   unchained(*before) if before else b"")
    if rng.random() < 0.15:   # the newest entry by someone is more than 64 KiB from the end
        for _ in range(3):
            data = APPENDS["a long app entry"](data, rng)
    for _ in range(rng.randint(0, 4)):
        data = rng.choice(list(APPENDS.values()))(data, rng)
    return data + rng.choice(TAILS)


def test_the_last_action_is_what_the_shared_reader_gives_for_random_journals(tmp_path):
    """400 journals from a fixed seed, each with the shapes random_journal draws, among them some past the 64 KiB the reader
    first looks at, so it reads further back: the public reader gives the newest entry by someone that entries() gives, and
    None when entries() gives none. The run holds all three kinds of journal, so a change to the reader can't pass by
    answering the same for each, and some journals with no chain that end in UTF-16 JSON, which format 2's parse would
    read if the reader didn't drop a last line holding 0x00."""
    rng = random.Random(20261024)
    long, found, empty, utf16 = 0, 0, 0, 0
    for n in range(400):
        path = tmp_path / f"{n}.jsonl"
        data = random_journal(rng)
        path.write_bytes(data)
        last = journal_module.last_action(path)
        assert last == given_last(path), n
        long += len(data) > 65_536
        found += last is not None
        empty += last is None
        utf16 += data.endswith(UTF16_NOTE) and b'"prev"' not in data
    assert long >= 20 and found >= 100 and empty >= 20 and utf16 >= 3, (long, found, empty, utf16)
