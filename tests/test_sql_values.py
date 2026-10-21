"""The SQL literal helper, the bulk insert behind ID lists and derived tables, and the cost of a bound
parameter."""

import importlib
import importlib.machinery
import sys

import duckdb
import pytest

import glessner
from glessner.events import id_table, insert_columns, sql_literal


class Searches:
    """A finder first on the import path that records each module name the import system searches for."""

    def __init__(self):
        self.names = []

    def find_spec(self, name, path=None, target=None):
        self.names.append(name)


class InstalledPandas:
    """A finder first on the import path that finds pandas, without loading anything."""

    def find_spec(self, name, path=None, target=None):
        return importlib.machinery.ModuleSpec(name, None) if name == "pandas" else None


def test_a_bound_parameter_searches_the_import_path_for_nothing(monkeypatch):
    """DuckDB 1.5.6 tries to import pandas for each value it binds, and each failed try searched the import path: 1.5 ms
    a parameter. The package caches the failure (see its __init__). With pandas installed, the first bind imports it."""
    con = duckdb.connect()
    con.execute("SELECT ?", [1]).fetchall()
    searches = Searches()
    monkeypatch.setattr(sys, "meta_path", [searches, *sys.meta_path])
    con.execute("SELECT ?, ?, ?, ?", [1, "text", 2.5, None]).fetchall()
    assert searches.names == []


def test_an_installed_pandas_is_left_alone(monkeypatch):
    monkeypatch.delitem(sys.modules, "pandas", raising=False)
    monkeypatch.setattr(sys, "meta_path", [InstalledPandas(), *sys.meta_path])
    importlib.reload(glessner)
    assert "pandas" not in sys.modules


def test_literals():
    assert sql_literal(None) == "NULL"
    assert sql_literal(True) == "true" and sql_literal(False) == "false"
    assert sql_literal(42) == "42" and sql_literal(-2.5) == "-2.5"
    assert sql_literal("it's") == "'it''s'"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), b"bytes", ["list"], "nul\x00byte"])
def test_unsupported_values_are_refused(bad):
    with pytest.raises((TypeError, ValueError)):
        sql_literal(bad)


def test_injection_shaped_values_stay_data():
    con = duckdb.connect()
    con.execute("CREATE TABLE victim (x INTEGER)")
    hostile = ["'); DROP TABLE victim; --", "a' OR '1'='1", "\\'", "O'Brien", "C:\\Users\\it's\\file.txt"]
    name = id_table(con, "ids", hostile)
    assert [v for (v,) in con.execute(f"SELECT v FROM {name} ORDER BY rowid").fetchall()] == hostile
    assert con.execute("SELECT count(*) FROM victim").fetchone()[0] == 0   # still exists


def test_insert_columns_keeps_every_value_its_type_and_order():
    """One JSON parameter carries text as it is, NUL characters included, which a literal refused, and each column
    takes the table's own type."""
    con = duckdb.connect()
    con.execute("CREATE TABLE t (a VARCHAR, b BIGINT, c BOOLEAN, d INTEGER)")
    text = ["it's", 'a "quote"', "C:\\Users\\x", "é and 日本", "nul\x00byte", "line\r\nbreak\u2028", "", None]
    numbers = [2**62, -1, None, 0, 7, 8, 9, 10]
    flags = [True, False, None, True, False, True, False, True]
    small = list(range(8))
    insert_columns(con, "t", text, numbers, flags, small)
    assert con.execute("SELECT * FROM t ORDER BY rowid").fetchall() == list(zip(text, numbers, flags, small, strict=True))
    insert_columns(con, "t", [], [], [], [])   # nothing to insert
    with pytest.raises(ValueError):   # a column for each of the table's, no more and no fewer
        insert_columns(con, "t", ["x"], [1])
    many = [f"{i:032x}" for i in range(25_001)]
    name = id_table(con, "ids", iter(many))
    assert [v for (v,) in con.execute(f"SELECT v FROM {name} ORDER BY rowid").fetchall()] == many
    assert id_table(con, "ids", []) == "ids" and con.execute("SELECT count(*) FROM ids").fetchone()[0] == 0
