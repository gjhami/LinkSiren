"""
Unit tests for the `get_rankings` function from the `linksiren.impure_functions` module.
This module contains tests to verify the behavior of the `get_rankings` function under various
conditions, including successful execution and different types of failures.
Fixtures:
    smb_connection_mock: A mock object for simulating an SMB connection.
    host_target: A fixture that provides a `HostTarget` instance with predefined paths and a mock
    connection.
Tests:
    - test_get_rankings_no_connection: Verifies that `get_rankings` returns an empty dictionary
      when there is no connection.
    - test_get_rankings_connection_failure: Verifies that `get_rankings` returns an empty dictionary
      when the connection attempt fails.
    - test_get_rankings_expand_paths_failure: Verifies that `get_rankings` returns an empty
      dictionary when expanding paths fails.
    - test_get_rankings_review_all_folders_failure: Verifies that `get_rankings` returns an empty
      dictionary when reviewing all folders fails.
    - test_get_rankings_success: Verifies that `get_rankings` returns the correct rankings when
      executed successfully.
    - test_get_rankings_go_fast: Verifies that `get_rankings` returns the correct rankings when
      executed in "go fast" mode with nested folders.
"""

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import pytest
from linksiren.impure_functions import get_rankings
from linksiren.target import HostTarget


@pytest.fixture
def smb_connection_mock():
    """
    Creates a mock object for an SMB connection.

    Returns:
        MagicMock: A mock object simulating an SMB connection.
    """
    return MagicMock()


@pytest.fixture(scope="function")
def host_target(smb_connection_mock):
    """
    Creates and returns a HostTarget object with predefined host and paths.

    Args:
        smb_connection_mock: A mock object representing the SMB connection.

    Returns:
        HostTarget: An instance of HostTarget with the specified host and paths.
    """
    target = HostTarget(host="test_host", connection=smb_connection_mock)
    target.paths = ["share\\folder1", "share\\folder2"]
    return target


def test_get_rankings_no_connection(host_target):
    """
    Test the get_rankings function when there is no connection.

    This test sets the connection attribute of the host_target to None and
    verifies that the get_rankings function returns an empty dictionary.

    Args:
        host_target: A mock or fixture representing the target host.

    Asserts:
        The result of get_rankings is an empty dictionary when there is no connection.
    """
    host_target.connection = None
    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False, ["C$"])
    assert result == {}


def test_get_rankings_connection_failure(host_target):
    """
    Test case for get_rankings function to handle connection failure.

    This test simulates a connection failure scenario by setting the host_target's
    connection to None and mocking the 'connect' method to raise an Exception.
    It verifies that the get_rankings function returns an empty dictionary when
    the connection cannot be established.

    Args:
        host_target: The target host object with connection attributes.

    Asserts:
        The result of get_rankings is an empty dictionary when connection fails.
    """
    host_target.connection = None
    targets = [host_target]
    with patch.object(host_target, "connect", side_effect=Exception("Connection failed")):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_expand_paths_failure(host_target):
    """
    Test the `get_rankings` function to ensure it handles the failure of the `expand_paths` method.

    This test simulates a scenario where the `expand_paths` method of the `host_target` object
    raises an exception. It verifies that the `get_rankings` function returns an empty dictionary
    when this exception occurs.

    Args:
        host_target: The target host object whose `expand_paths` method will be patched to raise an
        exception.

    Asserts:
        The result of the `get_rankings` function is an empty dictionary when `expand_paths` fails.
    """
    targets = [host_target]
    with patch.object(host_target, "expand_paths", side_effect=Exception("Expand paths failed")):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_review_all_folders_failure(host_target):
    """
    Test case for get_rankings function when review_all_folders method fails.

    This test ensures that the get_rankings function handles the failure of the
    review_all_folders method gracefully by returning an empty dictionary.

    Args:
        host_target: The target host object whose review_all_folders method will be patched to
        raise an exception.

    Setup:
        - Patches the review_all_folders method of the host_target to raise an Exception with
          the message "Review folders failed".

    Test:
        - Calls the get_rankings function with the patched host_target.
        - Asserts that the result is an empty dictionary.
    """
    targets = [host_target]
    with patch.object(
        host_target,
        "review_all_folders",
        side_effect=Exception("Review folders failed"),
    ):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_success(host_target):
    """
    Test the `get_rankings` function for a successful scenario.

    This test simulates a scenario where the `get_rankings` function is called with a target host
    that has one folder containing an active file and another folder that is empty. The function
    should return a dictionary with the folder paths as keys and the number of active files as
    values.

    Args:
        host_target (MagicMock): A mock object representing the target host.

    Assertions:
        Asserts that the result of `get_rankings` matches the expected dictionary with folder paths
        and their corresponding active file counts.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    folder1_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        )
    ]
    folder2_contents = []
    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents]
    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", now - timedelta(days=2), 1, False)
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder2": 0,
    }


def test_get_rankings_go_fast(host_target):
    """
    Test the `get_rankings` function to ensure it correctly ranks directories and files based on
    their access times. This test sets up a mock file system structure with various files and
    directories, each having different access times. It then verifies that the `get_rankings`
    function correctly calculates the rankings based on the provided criteria.

    Args:
        host_target (MagicMock): A mock object representing the host target with a connection
                                 attribute that simulates the behavior of listing directory
                                 contents.

    The mock file system structure is as follows:
    - folder1
        - file1.txt (active)
        - file2.txt (inactive)
        - subfolder1 (active)
            - subfolder2 (active)
        - subfolder3 (active)
            - file1.txt (active)
            - file2.txt (active)
            - file2.txt (inactive)
    - folder2 (empty)

    The `listPath` method of the host_target's connection is set to return the contents of these
    folders in sequence. The test asserts that the `get_rankings` function returns the correct
    rankings for each directory based on the access times of the files and directories within them.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    folder1_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: inactive_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder1",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder3",
            get_atime_epoch=lambda: active_time,
        ),
    ]
    subfolder1_contents = [
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder2",
            get_atime_epoch=lambda: active_time,
        )
    ]
    subfolder2_contents = []
    subfolder3_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: inactive_time,
        ),
    ]
    folder2_contents = []

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [
        folder1_contents,
        subfolder1_contents,
        subfolder2_contents,
        subfolder3_contents,
        folder2_contents,
    ]

    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", now - timedelta(days=2), 3, True)
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder1\\subfolder1": 0,
        "\\\\test_host\\share\\folder1\\subfolder1\\subfolder2": 0,
        "\\\\test_host\\share\\folder1\\subfolder3": 1,
        "\\\\test_host\\share\\folder2": 0,
    }
