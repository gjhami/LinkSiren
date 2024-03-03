# Test check for active files
from datetime import datetime, timezone
import pytest
from linksiren.pure_functions import is_active_file

def test_zero_threshold():
    # Test threshold date is the same as the access time
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709251200
    expected_result = True
    assert is_active_file(threshold_date, access_time) == expected_result

def test_before_threshold():
    # Test access time is before the threshold date
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709164800
    expected_result = False
    assert is_active_file(threshold_date, access_time) == expected_result

def test_after_threshold():
    # Test access time is after the threshold date
    threshold_date = datetime.fromtimestamp(1709251200)
    access_time = 1709337600
    expected_result = True
    assert is_active_file(threshold_date, access_time) == expected_result