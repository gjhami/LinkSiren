from unittest.mock import patch, mock_open
from linksiren.impure_functions import read_targets


def test_read_targets_success():
    targets_file = "targets.txt"
    mock_targets = "target1\ntarget2\n"
    expected_targets = ["target1", "target2"]

    with patch("builtins.open", mock_open(read_data=mock_targets)):
        with patch(
            "linksiren.pure_functions.process_targets", return_value=expected_targets
        ) as mock_process_targets:
            result = read_targets(targets_file)
            assert result == expected_targets
            mock_process_targets.assert_called_once_with(expected_targets)


def test_read_targets_file_not_found():
    targets_file = "non_existent_targets.txt"

    with patch("builtins.open", side_effect=FileNotFoundError):
        with patch("linksiren.pure_functions.process_targets", return_value=[]):
            result = read_targets(targets_file)
            assert result == []


def test_read_targets_empty_file():
    targets_file = "empty_targets.txt"
    mock_targets = ""
    expected_targets = []

    with patch("builtins.open", mock_open(read_data=mock_targets)):
        with patch(
            "linksiren.pure_functions.process_targets", return_value=expected_targets
        ) as mock_process_targets:
            result = read_targets(targets_file)
            assert result == expected_targets
            mock_process_targets.assert_called_once_with(expected_targets)


def test_read_targets_permission_error():
    targets_file = "targets.txt"

    with patch("builtins.open", side_effect=PermissionError):
        with patch("linksiren.pure_functions.process_targets", return_value=[]):
            result = read_targets(targets_file)
            assert result == []
