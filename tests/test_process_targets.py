"""
This module contains unit tests for the `process_targets` function from the
`linksiren.pure_functions` module. The tests ensure that the function correctly processes UNC
paths into `HostTarget` objects.
Fixtures:
    unc_paths: Provides a list of UNC paths for testing.
    expected_targets: Provides a list of expected `HostTarget` objects corresponding to the
        `unc_paths`.
Tests:
    test_process_targets: Verifies that `process_targets` correctly processes a list of UNC paths.
    test_process_targets_empty: Verifies that `process_targets` returns an empty list when given an
        empty list.
    test_process_targets_single_path: Verifies that `process_targets` correctly processes a single
        UNC path.
    test_process_targets_multiple_hosts: Verifies that `process_targets` correctly processes UNC
        paths from multiple hosts.
    test_process_targets_duplicate_paths: Verifies that `process_targets` correctly handles
        duplicate UNC paths.
"""
import pytest
from linksiren.target import HostTarget
from linksiren.pure_functions import process_targets


@pytest.fixture
def unc_paths():
    """
    Returns a list of UNC (Universal Naming Convention) paths.

    The paths are in the format of \\\\host\\share\\folder, representing network
    locations on different hosts and shares.

    Returns:
        list: A list of strings, each representing a UNC path.
    """
    return [
        r"\\host1\share1\folder1",
        r"\\host1\share1\folder2",
        r"\\host2\share2\folder1",
        r"\\host3\share3\folder1",
        r"\\host3\share3\folder2",
        r"\\host3\share3\folder3",
    ]


@pytest.fixture
def expected_targets():
    """
    Returns a list of HostTarget objects representing expected targets.

    Each HostTarget object contains a host name and a list of paths associated with that host.

    Returns:
        list: A list of HostTarget objects with predefined host names and paths.
    """
    return [
        HostTarget(host="host1", paths=["share1\\folder1", "share1\\folder2"]),
        HostTarget(host="host2", paths=["share2\\folder1"]),
        HostTarget(
            host="host3",
            paths=["share3\\folder1", "share3\\folder2", "share3\\folder3"],
        ),
    ]


def test_process_targets(unc_paths, expected_targets):
    """
    Test the process_targets function.

    Args:
        unc_paths (list): A list of UNC paths to be processed.
        expected_targets (list): A list of expected target objects.

    Asserts:
        The number of targets matches the number of expected targets.
        Each target's host matches the expected target's host.
        Each target's paths, when sorted, match the expected target's paths.
    """
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)


def test_process_targets_empty():
    """
    Test the process_targets function with an empty list.

    This test ensures that when an empty list is passed to the process_targets
    function, it returns an empty list as expected.
    """
    targets = process_targets([])
    assert not targets


def test_process_targets_single_path():
    """
    Test the process_targets function with a single UNC path.

    This test verifies that the process_targets function correctly processes
    a single UNC path and returns the expected HostTarget object.

    The test checks:
    - The number of targets returned by process_targets matches the expected number.
    - Each target's host matches the expected host.
    - Each target's paths match the expected paths (order-independent).

    The input UNC path used for this test is:
    - \\\\host1\\share1\\folder1

    The expected output is a list containing one HostTarget object with:
    - host: "host1"
    - paths: ["share1\\folder1"]
    """
    unc_paths = [r"\\host1\share1\folder1"]
    expected_targets = [HostTarget(host="host1", paths=["share1\\folder1"])]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)


def test_process_targets_multiple_hosts():
    """
    Test the `process_targets` function with multiple UNC paths.

    This test verifies that the `process_targets` function correctly processes
    multiple UNC paths and returns the expected list of `HostTarget` objects.

    Test Case:
    - Input: A list of UNC paths with different hosts.
    - Expected Output: A list of `HostTarget` objects with the correct host and paths.

    The test checks:
    1. The number of targets returned by `process_targets` matches the expected number.
    2. Each `HostTarget` object has the correct host.
    3. Each `HostTarget` object has the correct paths, sorted for comparison.

    UNC Paths:
    - \\\\host1\\share1\\folder1
    - \\\\host2\\share2\\folder1

    Expected Targets:
    - HostTarget(host="host1", paths=["share1\\folder1"])
    - HostTarget(host="host2", paths=["share2\\folder1"])
    """
    unc_paths = [r"\\host1\share1\folder1", r"\\host2\share2\folder1"]
    expected_targets = [
        HostTarget(host="host1", paths=["share1\\folder1"]),
        HostTarget(host="host2", paths=["share2\\folder1"]),
    ]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)


def test_process_targets_duplicate_paths():
    """
    Test the `process_targets` function to ensure it correctly handles duplicate UNC paths.

    This test checks that when given a list of UNC paths with duplicates, the `process_targets`
    function returns the expected list of `HostTarget` objects without duplicates.

    Test Case:
    - Input: A list of UNC paths with duplicates.
    - Expected Output: A list of `HostTarget` objects with unique paths.

    Assertions:
    - The number of targets returned by `process_targets` matches the expected number of targets.
    - Each `HostTarget` object in the returned list has the correct host and paths, with paths
        sorted.

    Example:
    """
    unc_paths = [r"\\host1\share1\folder1", r"\\host1\share1\folder1"]
    expected_targets = [HostTarget(host="host1", paths=["share1\\folder1"])]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)
