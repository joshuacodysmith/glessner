"""A RECmd Services row hosted in svchost takes its Same file key from its ServiceDLL, else from its image path, and
no event ID changes, as the pinned IDs below show. An existing case picks the key up at its next rebuild."""

import pivot_key_fixtures as fx

# The IDs the rows below give, pinned so the ServiceDLL key can't move them. An ID hashes the host, artifact, source
# file, source record, and time description; none of them is the file path or its key.
GOLDEN = {
    "svchost dll": "422294c221a2ccc9ae88bbc283d5c3e7",
    "svchost quoted dll": "9737e6cc4d17a308f6cb45b0c369c607",
    "svchost no dll": "3a12a8a1c76848beccffdbc74ec12220",
    "svchost bare dll": "753abd7835e68aa9e5c267c1150f8e17",
    "own image with dll": "f4a929afb9d308909ec7e0071d4d3efa",
    "svchost mixed case": "f33952438c19a19ee0cbac05ee798db4",
    "svchost two dlls": "de8095cfa3f194ba9ad145c58861c100",
    "svchost empty parameter dll": "6aca83dffc55ea41a4b70b72210ffda7",
}
ROWS = {
    "svchost dll": (r"%SystemRoot%\system32\svchost.exe -k netsvcs", r"%SystemRoot%\System32\aelupsvc.dll"),
    "svchost quoted dll": (r'"C:\Windows\System32\svchost.exe" -k LocalService', r'"C:\Windows\System32\Windows.Storage.dll"'),
    "svchost no dll": (r"%SystemRoot%\system32\svchost.exe -k netsvcs", ""),
    "svchost bare dll": (r"%SystemRoot%\system32\svchost.exe -k netsvcs", "nosuchpath.dll"),
    "own image with dll": (r"C:\Program Files\Vendor\svc.exe", r"C:\Program Files\Vendor\svc.dll"),
    "svchost mixed case": (r"C:\WINDOWS\System32\SvcHost.EXE -k netsvcs", r"%SystemRoot%\System32\Msi.dll"),
    # RECmd writes both values when a service has ServiceDll in its key and in its Parameters subkey (EventLog, DHCP, TrkWks)
    "svchost two dlls": (r"%SystemRoot%\system32\svchost.exe -k LocalService",
                         r"Services ServiceDll: %SystemRoot%\System32\old.dll / "
                         r"Parameter ServiceDll: %SystemRoot%\System32\wevtsvc.dll"),
    "svchost empty parameter dll": (r"%SystemRoot%\system32\svchost.exe -k LocalService",
                                    r"Services ServiceDll: %SystemRoot%\System32\dhcpcore.dll / Parameter ServiceDll:"),
}


def service_events(tmp_path):
    out = fx.folder_of(tmp_path, "recmd")
    rows = [fx.recmd_row("Services", fx.SERVICES, "", f"Name: {name} Desc: ", f"Image path: {image} ServiceDLL: {dll}")
            for name, (image, dll) in ROWS.items()]
    fx.csv_file(out / "recmd.csv", fx.RECMD_COLUMNS, rows)
    return dict(zip(ROWS, fx.run("recmd_csv", out), strict=True))


def test_a_svchost_hosted_service_is_keyed_from_its_service_dll(tmp_path):
    got = {name: (e.file_path, e.file_key) for name, e in service_events(tmp_path).items()}
    assert got["svchost dll"] == (r"C:\Windows\System32\aelupsvc.dll", r"\windows\system32\aelupsvc.dll")
    assert got["svchost quoted dll"] == (r"C:\Windows\System32\Windows.Storage.dll", r"\windows\system32\windows.storage.dll")
    assert got["svchost mixed case"][1] == r"\windows\system32\msi.dll"
    # Two ServiceDlls: the Parameters subkey's, which svchost reads first, else the one in the service's own key
    assert got["svchost two dlls"] == (r"C:\Windows\System32\wevtsvc.dll", r"\windows\system32\wevtsvc.dll")
    assert got["svchost empty parameter dll"][1] == r"\windows\system32\dhcpcore.dll"
    # No ServiceDLL, or one that names no folder to key: the image path
    assert got["svchost no dll"] == (r"C:\Windows\system32\svchost.exe", r"\windows\system32\svchost.exe")
    assert got["svchost bare dll"][1] == r"\windows\system32\svchost.exe"
    # A service that is its own program keeps that program, whatever its row says about a DLL
    assert got["own image with dll"][1] == r"\program files\vendor\svc.exe"


def test_the_service_dll_key_changes_no_event_id(tmp_path):
    """A mark in a journal names its event by ID, so keying a row from its DLL must not orphan the marks on it."""
    assert fx.named_ids(service_events(tmp_path)) == GOLDEN
