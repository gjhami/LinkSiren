# Test for computing the cutoff date for active files
from datetime import datetime
import pytest
from linksiren.pure_functions import compute_threshold_date

@pytest.fixture
def valid_test_cases():
    # Test cases for is_valid_payload_name
    # Format: (date, threshold_length, expected_threshold_date)
    # date is a datetime object
    # threshold_length is an integer representing a number of days to subtract from the date
    # expected_threshold_date is a datetime object representing the expected result of the computation

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
    date = datetime(1950, 7, 1)
    threshold = 0
    expected_threshold_date = datetime(1950, 7, 1)

    assert(compute_threshold_date(date, threshold) == expected_threshold_date)

def test_negative_threshold():
    date = datetime(1990, 3, 1)
    threshold = -10
    expected_threshold_date = datetime(1990, 3, 11)

    assert(compute_threshold_date(date, threshold) == expected_threshold_date)

def test_valid_cases(valid_test_cases):
    for date, threshold, expected_threshold_date in valid_test_cases:
        assert(compute_threshold_date(date, threshold) == expected_threshold_date)