"""
Unit tests for the `is_active_file` function from the `linksiren.pure_functions` module.

These tests verify the behavior of the `is_active_file` function under different conditions:
- When the access time is exactly the same as the threshold date.
- When the access time is before the threshold date.
- When the access time is after the threshold date.

Each test case compares the function's output to the expected result to ensure correctness.
"""

from datetime import datetime
from linksiren.pure_functions import is_active_file


def test_zero_threshold():
    """
    Test the `is_active_file` function with a threshold date that is the same as the access time.

    This test checks if the function correctly identifies a file as active when the threshold date
    is exactly equal to the access time.

    Test Case:
    - threshold_date: 1709251200 (converted to datetime)
    - access_time: 1709251200
    - expected_result: True

    The test asserts that the `is_active_file` function returns True when the threshold date and
    access time are the same.
    """
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709251200
    expected_result = True
    assert is_active_file(threshold_date, access_time) == expected_result


def test_before_threshold():
    """
    Test the `is_active_file` function to ensure it returns False when the access time is
    before the threshold date.

    This test sets a threshold date and an access time that is earlier than the threshold.
    It then checks if the `is_active_file` function correctly identifies that the file is not
    active.

    Test Case:
    - threshold_date: A specific date and time (converted from timestamp 1709251200).
    - access_time: A timestamp (1709164800) representing a time before the threshold date.
    - expected_result: False, since the access time is before the threshold date.

    Assertions:
    - Asserts that `is_active_file(threshold_date, access_time)` returns False.
    """
    # Test access time is before the threshold date
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709164800
    expected_result = False
    assert is_active_file(threshold_date, access_time) == expected_result


def test_after_threshold():
    """
    Test the `is_active_file` function to ensure it returns True when the access time is after
    the threshold date.

    This test sets a threshold date and an access time that is after the threshold date.
    It then asserts that the `is_active_file` function returns True, indicating the file is active.

    Test Case:
    - threshold_date: A datetime object representing the threshold date.
    - access_time: An integer representing the access time (in seconds since epoch).
    - expected_result: True, since the access time is after the threshold date.
    """
    # Test access time is after the threshold date
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709337600
    expected_result = True
    assert is_active_file(threshold_date, access_time) == expected_result
