"""
This module contains unit tests for the `filter_targets` function from the
`linksiren.pure_functions` module. The tests are designed to verify the correctness of the function
under various scenarios.
Fixtures:
    sorted_rankings: A pytest fixture that returns a dictionary of folder paths and their rankings,
                     sorted in descending order of rankings.
    host_targets: A pytest fixture that returns a list of `HostTarget` instances, each representing
                  a host and its associated folder paths.
Test Cases:
    test_single_target_single_folder: Tests filtering when there is a single target with a single
                                      folder allowed.
    test_single_target_multi_folder: Tests filtering when there is a single target with multiple
                                     folders allowed.
    test_multi_target_single_folder: Tests filtering when there are multiple targets with a single
                                     folder allowed per target.
    test_multi_target_multi_folder: Tests filtering when there are multiple targets with multiple
                                    folders allowed per target.
    test_filter_targets_empty_targets: Tests filtering when the targets list is empty.
    test_filter_targets_empty_rankings: Tests filtering when the rankings dictionary is empty.
    test_filter_targets_zero_max_folders: Tests filtering when the maximum number of folders per
                                          target is zero.
    test_filter_targets_max_folders_greater_than_rankings: Tests filtering when the maximum number
                                                           of folders per target is greater than
                                                           the number of available rankings.
"""

import pytest
from linksiren.pure_functions import filter_targets
from linksiren.target import HostTarget  # Import the HostTarget class


@pytest.fixture
def sorted_rankings():
    """
    Sorts and returns a dictionary of folder paths with their corresponding rankings in descending
    order. The function defines a dictionary with folder paths as keys and their rankings as
    values. It then sorts this dictionary based on the rankings in descending order and
    returns the sorted dictionary.

    Returns:
        dict: A dictionary with folder paths as keys and their rankings as values, sorted in
              descending order.
    """
    rankings = {
        # Host 1
        "\\\\host1\\share1\\folder1": 8,
        "\\\\host1\\share1\\folder2": 9,
        "\\\\host1\\share1\\folder3": 9,
        "\\\\host1\\share2\\folder1": 10,
        "\\\\host1\\share2\\folder2": 3,
        "\\\\host1\\share2\\folder3": 2,
        "\\\\host1\\share2\\folder4": 1,
        "\\\\host1\\share3\\folder1": 6,
        "\\\\host1\\share3\\folder2": 2,
        # Host 2
        "\\\\host2\\share1\\folder1": 8,
        "\\\\host2\\share1\\folder2": 8,
        "\\\\host2\\share1\\folder3": 5,
        "\\\\host2\\share2\\folder1": 10,
        "\\\\host2\\share2\\folder2": 3,
        "\\\\host2\\share2\\folder3": 2,
        "\\\\host2\\share2\\folder4": 11,
        "\\\\host2\\share3\\folder1": 6,
        "\\\\host2\\share3\\folder2": 2,
        # Host 3
        "\\\\host3\\share1\\folder1": 8,
        "\\\\host3\\share1\\folder2": 1,
        "\\\\host3\\share1\\folder3": 5,
        "\\\\host3\\share2\\folder1": 10,
        "\\\\host3\\share2\\folder2": 3,
        "\\\\host3\\share2\\folder3": 2,
        "\\\\host3\\share2\\folder4": 1,
        "\\\\host3\\share3\\folder1": 8,
        "\\\\host3\\share3\\folder2": 2,
    }
    rankings = dict(sorted(rankings.items(), key=lambda item: item[1], reverse=True))
    return rankings


@pytest.fixture
def host_targets():
    """
    Create and return a list of HostTarget instances.

    Each HostTarget instance represents a host with associated paths.

    Returns:
        list: A list containing three HostTarget instances with predefined hosts and paths.
    """
    # Create HostTarget instances
    host1 = HostTarget(
        host="host1", paths=["share1\\folder1", "share1\\folder2", "share1\\folder3"]
    )
    host2 = HostTarget(
        host="host2",
        paths=[
            "share2\\folder1",
            "share2\\folder2",
            "share2\\folder3",
            "share2\\folder4",
        ],
    )
    host3 = HostTarget(host="host3", paths=["share3\\folder1", "share3\\folder2"])
    return [host1, host2, host3]


def test_single_target_single_folder(sorted_rankings, host_targets):
    """
    Test the filter_targets function with a single target and a single folder.

    Args:
        sorted_rankings (list): A list of sorted rankings.
        host_targets (list): A list of host targets.

    Test Case:
        - Use a single target from host_targets.
        - Set max_folders_per_target to 1.
        - Expect the result to be a specific folder path.

    Asserts:
        The result of filter_targets matches the expected_result.
    """
    targets = [host_targets[1]]
    max_folders_per_target = 1
    expected_result = ["\\\\host2\\share2\\folder4"]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result


def test_single_target_multi_folder(sorted_rankings, host_targets):
    """
    Test the filter_targets function with a single target and multiple folders.

    This test checks if the function correctly filters and sorts folders for a single target
    when there are multiple folders available. The maximum number of folders per target is set to 2.

    Args:
        sorted_rankings (list): A list of sorted rankings for the folders.
        host_targets (list): A list of host targets.

    Expected Result:
        The function should return a list of folders sorted as per the expected result.
    """
    targets = [host_targets[0]]
    max_folders_per_target = 2
    expected_result = ["\\\\host1\\share2\\folder1", "\\\\host1\\share1\\folder2"]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)


def test_multi_target_single_folder(sorted_rankings, host_targets):
    """
    Test the filter_targets function with multiple targets and a single folder per target.

    This test checks the behavior of the filter_targets function when provided with
    multiple HostTarget instances and a limit of one folder per target. It verifies
    that the function correctly filters and returns the expected list of folders.

    Args:
        sorted_rankings (list): A list of sorted rankings used for filtering.
        host_targets (list): A list of HostTarget instances to be filtered.

    Asserts:
        The result of the filter_targets function matches the expected list of folders.
    """
    targets = [
        host_targets[0],
        host_targets[2],
    ]  # Use HostTarget instances for share1 and share3
    max_folders_per_target = 1
    expected_result = [
        "\\\\host1\\share2\\folder1",
        "\\\\host3\\share2\\folder1",
    ]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)


def test_multi_target_multi_folder(sorted_rankings, host_targets):
    """
    Test the `filter_targets` function with multiple targets and multiple folders.

    This test verifies that the `filter_targets` function correctly filters and sorts
    folders from multiple targets based on the provided sorted rankings and a maximum
    number of folders per target.

    Args:
        sorted_rankings (list): A list of sorted rankings for the folders.
        host_targets (list): A list of HostTarget instances representing the targets.

    Expected Result:
        The function should return a list of folder paths that match the expected result,
        sorted in the correct order.

    Assertions:
        The result of the `filter_targets` function should match the expected result
        after sorting.
    """
    targets = [
        host_targets[0],
        host_targets[1],
    ]  # Use HostTarget instances for share1 and share2
    max_folders_per_target = 3
    expected_result = [
        "\\\\host1\\share2\\folder1",
        "\\\\host1\\share1\\folder2",
        "\\\\host1\\share1\\folder3",
        "\\\\host2\\share2\\folder4",
        "\\\\host2\\share2\\folder1",
        "\\\\host2\\share1\\folder1",
    ]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)


def test_filter_targets_empty_targets(sorted_rankings):
    """
    Test the filter_targets function with an empty list of targets.

    This test ensures that when the filter_targets function is provided with an
    empty list of targets, it returns an empty list as the result.

    Args:
        sorted_rankings (list): A list of sorted rankings to be used in the test.

    Asserts:
        The result of the filter_targets function is an empty list.
    """
    max_folders_per_target = 10
    result = filter_targets([], sorted_rankings, max_folders_per_target)
    assert result == []


def test_filter_targets_empty_rankings():
    """
    Test case for the filter_targets function when the rankings dictionary is empty.

    This test verifies that the filter_targets function returns an empty list
    when provided with a list of targets and an empty rankings dictionary.

    Args:
        None

    Returns:
        None
    """
    targets = ["share1", "share2"]
    max_folders_per_target = 5
    result = filter_targets(targets, {}, max_folders_per_target)
    assert result == []


def test_filter_targets_zero_max_folders(sorted_rankings, host_targets):
    """
    Test the filter_targets function with max_folders_per_target set to zero.

    This test ensures that when the maximum number of folders per target is set to zero,
    the filter_targets function returns an empty list.

    Args:
        sorted_rankings (list): A list of sorted rankings.
        host_targets (list): A list of HostTarget instances.

    Asserts:
        The result of filter_targets is an empty list.
    """
    targets = [
        host_targets[0],
        host_targets[1],
    ]  # Use HostTarget instances for share1 and share2
    max_folders_per_target = 0
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == []


def test_filter_targets_max_folders_greater_than_rankings(
    sorted_rankings, host_targets
):
    """
    Test the filter_targets function when the maximum number of folders per target is greater
    than the number of rankings.

    This test ensures that the filter_targets function correctly handles the case where the maximum
    number of folders allowed per target exceeds the number of available rankings. It verifies
    that the function returns the expected list of folder paths.

    Args:
        sorted_rankings (list): A list of sorted rankings.
        host_targets (list): A list of HostTarget instances.

    Asserts:
        The result of the filter_targets function matches the expected list of folder paths.
    """
    targets = [
        host_targets[0],
        host_targets[2],
    ]  # Use HostTarget instances for share1 and share3
    max_folders_per_target = 10
    expected_result = [
        "\\\\host1\\share1\\folder1",
        "\\\\host1\\share1\\folder2",
        "\\\\host1\\share1\\folder3",
        "\\\\host1\\share2\\folder1",
        "\\\\host1\\share2\\folder2",
        "\\\\host1\\share2\\folder3",
        "\\\\host1\\share2\\folder4",
        "\\\\host1\\share3\\folder1",
        "\\\\host1\\share3\\folder2",
        "\\\\host3\\share1\\folder1",
        "\\\\host3\\share1\\folder2",
        "\\\\host3\\share1\\folder3",
        "\\\\host3\\share2\\folder1",
        "\\\\host3\\share2\\folder2",
        "\\\\host3\\share2\\folder3",
        "\\\\host3\\share2\\folder4",
        "\\\\host3\\share3\\folder1",
        "\\\\host3\\share3\\folder2",
    ]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)
