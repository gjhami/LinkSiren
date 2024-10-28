"""
This module contains unit tests for the `get_sorted_rankings` function from the `linksiren.impure_functions`
module. The tests use the `pytest` framework and `unittest.mock` for mocking dependencies.
Fixtures:
    target_mock: A fixture that returns a MagicMock object representing a target with no connection.
    targets_list: A fixture that returns a list containing the `target_mock`.
Tests:
    test_get_sorted_rankings_no_connection: Tests `get_sorted_rankings` when there is no connection.
    test_get_sorted_rankings_with_connection: Tests `get_sorted_rankings` when there is a connection.
    test_get_sorted_rankings_expand_paths_failure: Tests `get_sorted_rankings` when `expand_paths` raises an exception.
    test_get_sorted_rankings_review_all_folders_failure: Tests `get_sorted_rankings` when `review_all_folders` raises an exception.
"""

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import pytest
from linksiren.impure_functions import get_sorted_rankings


@pytest.fixture
def target_mock():
    """
    Creates and returns a mock object with a `connection` attribute set to None.

    Returns:
        MagicMock: A mock object with a `connection` attribute.
    """
    target = MagicMock()
    target.connection = None
    return target


@pytest.fixture
def targets_list(target_mock):
    """
    Returns a list containing the provided target_mock object.

    Args:
        target_mock: The mock object to be included in the list.

    Returns:
        list: A list containing the target_mock object.
    """
    return [target_mock]


def test_get_sorted_rankings_no_connection(targets_list):
    """
    Test the `get_sorted_rankings` function when there is no connection.
    This test verifies that the `get_sorted_rankings` function returns an empty
    dictionary when the `sort_rankings` function is patched to return an empty
    dictionary. It also checks that the `sort_rankings` function is called once.

    Args:
        targets_list (list): A list of target items to be ranked.

    Asserts:
        - The result of `get_sorted_rankings` is an empty dictionary.
        - The `sort_rankings` function is called exactly once.
    """
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    with patch(
        "linksiren.pure_functions.sort_rankings", return_value={}
    ) as mock_sort_rankings:
        result = get_sorted_rankings(
            targets_list,
            domain,
            username,
            password,
            active_threshold_date,
            max_depth,
            go_fast,
        )
        assert not result
        mock_sort_rankings.assert_called_once()


def test_get_sorted_rankings_with_connection(targets_list):
    """
    Test the `get_sorted_rankings` function with a mocked connection.
    This test verifies that the `get_sorted_rankings` function correctly sorts rankings
    when provided with a list of targets that have a mocked connection. It ensures that
    the function returns the expected sorted rankings and that the `sort_rankings` function
    is called with the correct arguments.

    Args:
        targets_list (list): A list of target objects to be used in the test.

    Setup:
        - Mocks the connection for the first target in the `targets_list`.
        - Sets up the return value for the `review_all_folders` method of the mocked connection.
        - Patches the `sort_rankings` function to return a predefined sorted ranking.

    Assertions:
        - Asserts that the result of `get_sorted_rankings` matches the expected sorted ranking.
        - Asserts that the `sort_rankings` function is called once with the correct argument.
    """
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].connection = MagicMock()
    targets_list[0].review_all_folders.return_value = {
        "\\\\test_host\\share\\folder1": 1
    }

    with patch(
        "linksiren.pure_functions.sort_rankings",
        return_value={"\\\\test_host\\share\\folder1": 1},
    ) as mock_sort_rankings:
        result = get_sorted_rankings(
            targets_list,
            domain,
            username,
            password,
            active_threshold_date,
            max_depth,
            go_fast,
        )
        assert result == {"\\\\test_host\\share\\folder1": 1}
        mock_sort_rankings.assert_called_once_with({"\\\\test_host\\share\\folder1": 1})


def test_get_sorted_rankings_expand_paths_failure(targets_list):
    """
    Test case for `get_sorted_rankings` function to handle the scenario where
    expanding paths in the targets list raises an exception.
    This test ensures that when `expand_paths` method of the first target in
    the `targets_list` raises an exception, the `get_sorted_rankings` function
    handles it gracefully and returns an empty dictionary.

    Args:
        targets_list (list): A list of target objects where the first target's
                             `expand_paths` method is mocked to raise an exception.

    Setup:
        - Mocks the `expand_paths` method of the first target in `targets_list`
          to raise an exception.
        - Mocks the `sort_rankings` function to return an empty dictionary.

    Assertions:
        - Asserts that the result of `get_sorted_rankings` is an empty dictionary.
        - Asserts that `sort_rankings` is called once with an empty dictionary.
    """
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].expand_paths.side_effect = Exception("Error expanding paths")

    with patch(
        "linksiren.pure_functions.sort_rankings", return_value={}
    ) as mock_sort_rankings:
        result = get_sorted_rankings(
            targets_list,
            domain,
            username,
            password,
            active_threshold_date,
            max_depth,
            go_fast,
        )
        assert not result
        mock_sort_rankings.assert_called_once_with({})


def test_get_sorted_rankings_review_all_folders_failure(targets_list):
    """
    Test case for `get_sorted_rankings` function when `review_all_folders` method of the first target in the `targets_list` raises an exception.
    This test ensures that when an exception is raised during the review of all folders, the `get_sorted_rankings` function handles it gracefully and returns an empty dictionary.

    Args:
        targets_list (list): A list of target objects where the first target's `review_all_folders` method is mocked to raise an exception.

    Setup:
        - Mocks the `review_all_folders` method of the first target in `targets_list` to raise an exception.
        - Mocks the `sort_rankings` function to return an empty dictionary.

    Assertions:
        - Verifies that the result of `get_sorted_rankings` is an empty dictionary.
        - Ensures that the `sort_rankings` function is called once with an empty dictionary.
    """
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].review_all_folders.side_effect = Exception(
        "Error reviewing folders"
    )

    with patch(
        "linksiren.pure_functions.sort_rankings", return_value={}
    ) as mock_sort_rankings:
        result = get_sorted_rankings(
            targets_list,
            domain,
            username,
            password,
            active_threshold_date,
            max_depth,
            go_fast,
        )
        assert result == {}
        mock_sort_rankings.assert_called_once_with({})
