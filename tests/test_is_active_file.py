# Test check for active files
from datetime import datetime, timezone
import pytest
from linksiren.pure_functions import is_active_file

# Define a fixture to generate test cases
@pytest.fixture
def valid_test_cases():
    # A timestamp must be used to avoid tests that are dependent on the current timezone
    # It's worth noting the is_active_file function may not work exactly right
    # when it's being used to compare the current date in one time zone
    # to the access time of a file in a different time zone where the file is hosted.
    threshold_date = datetime.fromtimestamp(1709251200)
    # Test cases: (threshold_date, access_time, expected_result)
    return [
        (threshold_date, 1709164800, False),    # Access time before threshold date
        (threshold_date, 1709251200, True),     # Access time equal to threshold date
        (threshold_date, 1709337600, True),      # Access time after threshold date
        (threshold_date, 1710201600, True)     # Access time after threshold date
    ]

# Define the test function
def test_valid_dates(valid_test_cases):
    for threshold_date, access_time, expected_result in valid_test_cases:
        assert is_active_file(threshold_date, access_time) == expected_result