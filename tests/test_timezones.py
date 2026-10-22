"""Host time zones and the zone axes setting."""

import json
import sys

import pytest
from conftest import registry
from test_analysis_relations import open_case
from test_server import login, request

from glessner.events import load
from glessner.timezones import host_timezones, validate_axes, windows_to_iana

TZ = "ROOT\\ControlSet00{}\\Control\\TimeZoneInformation"


def add_zone(case, host, control_set, values, hive="Windows/System32/config/SYSTEM"):
    load(case.db_path, [registry(f"{host}/{hive}", TZ.format(control_set), name, value) for name, value in values.items()],
         host=host, tool="recmd", tool_version="t", run_id=f"tz-{host}-{control_set}-{hive}", replaces_sources=[],
         staging_dir=case.folder)


def test_a_windows_old_system_hive_does_not_mix_in(synthetic_case):
    """RECmd reads every hive under a host's folder. A Windows.old SYSTEM hive has the same key paths as the live one
    and its path sorts first, so its zone values must not mix with the live hive's."""
    add_zone(synthetic_case, "DESKTOP", 1, {"TimeZoneKeyName": "Pacific Standard Time", "Bias": "480"})
    add_zone(synthetic_case, "DESKTOP", 1, {"TimeZoneKeyName": "UTC", "Bias": "0"},
             hive="Windows.old/Windows/System32/config/SYSTEM")
    product = "ROOT\\ControlSet001\\Control\\ProductOptions"
    load(synthetic_case.db_path, [registry("DESKTOP/Windows.old/Windows/System32/config/SYSTEM", product, "ProductType",
                                           "ServerNT"),
                                  registry("DESKTOP/Windows/System32/config/SYSTEM", product, "ProductType", "WinNT")],
         host="DESKTOP", tool="recmd", tool_version="t", run_id="old-product", replaces_sources=[],
         staging_dir=synthetic_case.folder)
    con, _, identity = open_case(synthetic_case)
    zone = host_timezones(con)["DESKTOP"]
    assert (zone["windows"], zone["bias_minutes"]) == ("Pacific Standard Time", 480)
    assert identity.hosts["DESKTOP"].role == "Workstations"   # the live hive's WinNT, not the copy's ServerNT


@pytest.mark.skipif(sys.platform != "win32", reason="the mapping comes from the ICU that ships with Windows")
def test_windows_names_map_to_iana_through_icu():
    assert windows_to_iana("Pacific Standard Time") == "America/Los_Angeles"
    assert windows_to_iana("GMT Standard Time") == "Europe/London"
    assert windows_to_iana("Not A Zone") == ""


def test_host_zones_from_the_system_hive(synthetic_case):
    add_zone(synthetic_case, "DC01", 2, {"TimeZoneKeyName": "Tokyo Standard Time", "Bias": "-540"})
    add_zone(synthetic_case, "DC01", 1, {"TimeZoneKeyName": "Pacific Standard Time", "Bias": "480", "DaylightBias": "-60",
                                         "DaylightStart": "Month 3, week of month 2, day of week 0",
                                         "ActiveTimeBias": "420"})
    # Daylight saving turned off on the host: the IANA zone would apply it, so only the fixed Bias is used.
    add_zone(synthetic_case, "DESKTOP", 1, {"TimeZoneKeyName": "Pacific Standard Time", "Bias": "480",
                                            "DynamicDaylightTimeDisabled": "1"})
    # A bias east of UTC is negative, and is read as such when written as an unsigned DWORD: -120, summer in Berlin.
    add_zone(synthetic_case, "WS01", 1, {"TimeZoneKeyName": "W. Europe Standard Time", "Bias": "-60",
                                         "ActiveTimeBias": "4294967176"})
    con, _, identity = open_case(synthetic_case)
    zones = host_timezones(con)
    dc = zones["DC01"]   # the lowest-numbered control set wins
    assert (dc["windows"], dc["bias_minutes"], dc["dst_disabled"]) == ("Pacific Standard Time", 480, False)
    # The bias when the hive was last written, which Autoruns' local times are read at
    assert (dc["active_bias_minutes"], zones["DESKTOP"]["active_bias_minutes"]) == (420, None)
    assert zones["WS01"]["active_bias_minutes"] == -120
    assert dc["source"] == "SYSTEM hive ControlSet001\\Control\\TimeZoneInformation"
    assert dc["daylight_start"].startswith("Month 3")
    if sys.platform == "win32":
        assert dc["iana"] == "America/Los_Angeles"
    assert (zones["DESKTOP"]["iana"], zones["DESKTOP"]["dst_disabled"]) == ("", True)
    assert identity.hosts["DC01"].timezone == dc


def test_validate_axes():
    hosts = {"DC01", "DESKTOP"}
    assert validate_axes([{"host": "DC01"}, {"zone": "Europe/London"}, {"host": "DC01"}], hosts) == [
        {"host": "DC01"}, {"zone": "Europe/London"}]
    assert validate_axes([{"zone": "Etc/GMT+8"}, {"zone": "UTC"}], hosts) == [{"zone": "Etc/GMT+8"}, {"zone": "UTC"}]
    for bad in ([{"host": "NOPE"}], [{"zone": "Europe/London; DROP"}], [{"zone": "x", "host": "DC01"}], "Europe/London",
                [{"zone": f"Etc/GMT+{i}"} for i in range(7)]):
        with pytest.raises(ValueError):
            validate_axes(bad, hosts)


def test_zone_axes_saved_with_the_case(running):
    app, port, _ = running
    session = login(port, app)
    res, _ = request(port, "POST", "/api/setting", session=session,
                     body={"name": "time_zones", "value": [{"host": "DC01"}, {"zone": "Europe/London"}]})
    assert res.status == 200
    line = json.loads((app.case.folder / "journal.jsonl").read_text().splitlines()[-1])
    assert (line["action"], line["name"], line["value"]) == (
        "case_setting", "time_zones", [{"host": "DC01"}, {"zone": "Europe/London"}])
    meta = json.loads(request(port, "GET", "/api/meta", session=session)[1])
    assert meta["time_zones"] == [{"host": "DC01"}, {"zone": "Europe/London"}]
    assert all("timezone" in h for h in meta["hosts"])
    assert request(port, "POST", "/api/setting", session=session,
                   body={"name": "time_zones", "value": [{"host": "NOPE"}]})[0].status == 400
