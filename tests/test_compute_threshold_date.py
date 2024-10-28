"""
Author: George Hamilton
This module contains unit tests for the `compute_threshold_date` function from the
`linksiren.pure_functions` module. The tests cover various scenarios including:
1. Threshold within the same month.
2. Threshold crossing month boundary.
3. Threshold crossing year boundary.
4. Zero threshold.
5. Negative threshold.
Fixtures:
    valid_test_cases: Provides a list of tuples containing test cases with the format
    (date, threshold_length, expected_threshold_date).
Tests:
    test_zero_threshold: Tests the function with a zero threshold.
    test_negative_threshold: Tests the function with a negative threshold.
    test_valid_cases: Tests the function with a variety of valid test cases.
"""
from datetime import datetime
import pytest
from linksiren.pure_functions import compute_threshold_date

@pytest.fixture
def valid_test_cases():
    """
    Generate a list of valid test cases for the threshold date computation.
    Each test case is a tuple containing:
    - date: A datetime object representing the initial date.
    - threshold_length: An integer representing the number of days to subtract from the date.
    - expected_threshold_date: A datetime object representing the expected result of the
                               computation.
    Returns:
        list: A list of tuples, each containing (date, threshold_length, expected_threshold_date).
    """

    # Test case 1: Threshold within the same month
    date_1 = datetime(2024, 3, 20)
    threshold_length_1 = 10
    expected_threshold_date_1 = datetime(2024, 3, 10)

    # Test case 2: Threshold crossing month boundary
    date_2 = datetime(1900, 4, 1)
    threshold_length_2 = 20
    expected_threshold_date_2 = datetime(1900, 3, 12)

    # Test case 3: Threshold crossing year boundary
    date_3 = datetime(2010, 1, 15)
    threshold_length_3 = 20
    expected_threshold_date_3 = datetime(2009, 12, 26)

    return [
        (date_1, threshold_length_1, expected_threshold_date_1),
        (date_2, threshold_length_2, expected_threshold_date_2),
        (date_3, threshold_length_3, expected_threshold_date_3)
    ]

def test_zero_threshold():
    """
    Test case for compute_threshold_date function with a zero threshold.
    This test verifies that the compute_threshold_date function returns the
    correct date when the threshold is set to zero. The expected behavior is
    that the function should return the same date that was passed in.
    Test Scenario:
    - Input date: July 1, 1950
    - Threshold: 0
    - Expected output date: July 1, 1950
    Assertions:
    - The function should return the input date when the threshold is zero.
    """
    date = datetime(1950, 7, 1)
    threshold = 0
    expected_threshold_date = datetime(1950, 7, 1)

    assert compute_threshold_date(date, threshold) == expected_threshold_date

def test_negative_threshold():
    """
    Test the compute_threshold_date function with a negative threshold.
    This test checks if the function correctly computes the threshold date
    when given a negative threshold value. The expected behavior is that
    the function should add the absolute value of the threshold to the
    initial date.
    Test case:
    - Initial date: March 1, 1990
    - Threshold: -10
    - Expected threshold date: March 11, 1990
    """
    date = datetime(1990, 3, 1)
    threshold = -10
    expected_threshold_date = datetime(1990, 3, 11)

    assert compute_threshold_date(date, threshold) == expected_threshold_date

def test_valid_cases(valid_test_cases):
    """
    Tests the compute_threshold_date function with valid test cases.

    Args:
        valid_test_cases (list of tuples): A list where each tuple contains:
            - date (datetime): The initial date.
            - threshold (int): The threshold value to compute the threshold date.
            - expected_threshold_date (datetime): The expected result after applying the threshold.

    Asserts:
        The computed threshold date matches the expected threshold date for each test case.
    """
    for date, threshold, expected_threshold_date in valid_test_cases:
        assert compute_threshold_date(date, threshold) == expected_threshold_date
