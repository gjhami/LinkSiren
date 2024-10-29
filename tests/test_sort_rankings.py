"""
This module contains unit tests for the `sort_rankings` function from the
`linksiren.pure_functions` module. The `sort_rankings` function is expected to sort a dictionary
of folder rankings in descending order of their ranking values. The tests cover various scenarios
including:
- Empty dictionary
- None input
- Single entry dictionary
- Multiple entries with unique values
- Multiple entries with duplicate values
- Multiple entries with negative values

Each test function initializes a dictionary of folder rankings, defines the expected result, and
asserts that the output of `sort_rankings` matches the expected result.
"""

from linksiren.pure_functions import sort_rankings


def test_empty():
    """
    Test case for the sort_rankings function with an empty input.

    This test verifies that the sort_rankings function correctly handles the case
    where the input dictionary is empty. The expected result for this case is also
    an empty dictionary.
    """
    folder_rankings = {}
    expected_result = {}
    assert sort_rankings(folder_rankings) == expected_result


def test_none():
    """
    Test the sort_rankings function with a None input.

    This test case checks the behavior of the sort_rankings function when
    provided with a None value for folder_rankings. The expected result is
    an empty dictionary.

    Assertions:
        - The result of sort_rankings(None) should be an empty dictionary.
    """
    folder_rankings = None
    expected_result = {}
    assert sort_rankings(folder_rankings) == expected_result


def test_single():
    """
    Test the sort_rankings function with a single folder ranking.

    This test case checks if the sort_rankings function correctly handles
    a dictionary with a single folder and its ranking. The expected result
    should be the same as the input since there is only one folder to sort.

    Assertions:
        - The sorted rankings should match the expected result.
    """
    folder_rankings = {"Folder1": 10}
    expected_result = {"Folder1": 10}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_unique():
    """
    Test the sort_rankings function with a dictionary containing multiple unique folder rankings.

    This test checks if the sort_rankings function correctly sorts the folders by their rankings
    in descending order. The input dictionary contains three folders with unique rankings, and
    the expected result is a dictionary with the folders sorted by their rankings.

    Expected Result:
        {"Folder1": 10, "Folder3": 8, "Folder2": 5}
    """
    folder_rankings = {"Folder1": 10, "Folder2": 5, "Folder3": 8}
    expected_result = {"Folder1": 10, "Folder3": 8, "Folder2": 5}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_duplicate():
    """
    Test the sort_rankings function with multiple folders having duplicate rankings.

    This test checks if the sort_rankings function correctly sorts a dictionary of folder rankings
    when there are multiple folders with the same ranking value. The expected behavior is that
    folders with the same ranking should maintain their relative order as in the input dictionary.

    Test Data:
    - Input: {"Folder1": 10, "Folder2": 5, "Folder3": 10}
    - Expected Output: {"Folder1": 10, "Folder3": 10, "Folder2": 5}
    """
    folder_rankings = {"Folder1": 10, "Folder2": 5, "Folder3": 10}
    expected_result = {"Folder1": 10, "Folder3": 10, "Folder2": 5}
    assert sort_rankings(folder_rankings) == expected_result


def test_multiple_negatives():
    """
    Test case for the sort_rankings function with multiple negative values.

    This test checks if the sort_rankings function correctly sorts a dictionary
    of folder rankings where the values are negative. The expected result is a
    dictionary sorted in descending order based on the ranking values.

    Test Data:
    - Input: {"Folder1": -10, "Folder2": -5, "Folder3": -8}
    - Expected Output: {"Folder2": -5, "Folder3": -8, "Folder1": -10}
    """
    folder_rankings = {"Folder1": -10, "Folder2": -5, "Folder3": -8}
    expected_result = {"Folder2": -5, "Folder3": -8, "Folder1": -10}
    assert sort_rankings(folder_rankings) == expected_result
