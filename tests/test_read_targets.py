"""
Unit tests for the `read_targets` function from the `linksiren.impure_functions` module.
These tests cover the following scenarios:
- Successful reading of targets from a file.
- Handling of a non-existent targets file.
- Handling of an empty targets file.
- Handling of a permission error when attempting to read the targets file.
Each test uses the `unittest.mock` library to mock file operations and the `process_targets`
function from the `linksiren.pure_functions` module.
"""
from unittest.mock import patch, mock_open
from linksiren.impure_functions import read_targets


def test_read_targets_success():
    """
    Test the read_targets function for successful execution.
    This test verifies that the read_targets function correctly reads the targets
    from a file and processes them as expected. It uses mock objects to simulate
    the file reading and target processing.

    Steps:
    1. Define the path to the targets file and mock data for the file content.
    2. Define the expected list of targets after processing.
    3. Patch the built-in open function to return the mock file content.
    4. Patch the process_targets function to return the expected list of targets.
    5. Call the read_targets function with the targets file path.
    6. Assert that the result matches the expected list of targets.
    7. Verify that the process_targets function was called once with the expected targets.

    Mocks:
    - builtins.open: Simulates reading from a file.
    - linksiren.pure_functions.process_targets: Simulates processing the targets.

    Asserts:
    - The result from read_targets matches the expected list of targets.
    - The process_targets function is called once with the expected targets.
    """
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
    """
    Test case for read_targets function when the target file is not found.
    This test simulates the scenario where the specified targets file does not exist.
    It mocks the built-in open function to raise a FileNotFoundError and the
    linksiren.pure_functions.process_targets function to return an empty list.
    The test asserts that the read_targets function returns an empty list when the
    targets file is not found.
    """
    targets_file = "non_existent_targets.txt"

    with patch("builtins.open", side_effect=FileNotFoundError):
        with patch("linksiren.pure_functions.process_targets", return_value=[]):
            result = read_targets(targets_file)
            assert not result


def test_read_targets_empty_file():
    """
    Test the `read_targets` function when the targets file is empty.
    This test verifies that the `read_targets` function correctly handles an empty
    targets file by returning an empty list. It uses the `mock_open` function to
    simulate an empty file and patches the `process_targets` function to return an
    empty list. The test asserts that the result of `read_targets` matches the
    expected empty list and that `process_targets` is called once with the expected
    empty list.

    Steps:
    1. Define the path to the empty targets file.
    2. Mock the contents of the targets file as an empty string.
    3. Define the expected result as an empty list.
    4. Patch the `open` function to simulate reading from an empty file.
    5. Patch the `process_targets` function to return the expected empty list.
    6. Call the `read_targets` function with the path to the empty targets file.
    7. Assert that the result matches the expected empty list.
    8. Verify that `process_targets` is called once with the expected empty list.
    """
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
    """
    Test case for read_targets function to handle PermissionError.
    This test simulates a scenario where the targets file cannot be opened due to
    a permission error. It uses mocking to replace the built-in open function with
    one that raises a PermissionError. Additionally, it mocks the process_targets
    function to return an empty list. The test asserts that the read_targets function
    returns an empty list when it encounters a PermissionError.
    Tested function:
    - read_targets(targets_file: str) -> list
    Mocks:
    - builtins.open: Raises PermissionError.
    - linksiren.pure_functions.process_targets: Returns an empty list.
    Asserts:
    - The result of read_targets is an empty list when a PermissionError is raised.
    """
    targets_file = "targets.txt"

    with patch("builtins.open", side_effect=PermissionError):
        with patch("linksiren.pure_functions.process_targets", return_value=[]):
            result = read_targets(targets_file)
            assert not result
