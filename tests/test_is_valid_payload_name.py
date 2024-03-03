# Test for payload name validation
import pytest
from linksiren.pure_functions import is_valid_payload_name

@pytest.fixture
def available_extensions():
    return ['.searchConnector-ms', '.library-ms', '.url', '.lnk']

def test_empty_name(available_extensions):
    assert(is_valid_payload_name('', available_extensions) == False)

def test_no_extension(available_extensions):
    assert(is_valid_payload_name('test', available_extensions) == False)

def test_valid_invalid_extension(available_extensions):
    assert(is_valid_payload_name('test.library-ms.urls', available_extensions) == False)

def test_invalid_valid_extension(available_extensions):
    assert(is_valid_payload_name('test.urls.library-mss', available_extensions) == False)

def test_invalid_extension(available_extensions):
    assert(is_valid_payload_name('test.libary-mss', available_extensions) == False)

def test_valid_extensions(available_extensions):
    for extension in available_extensions:
        filename = f'test.{extension}'
        assert(is_valid_payload_name(filename, available_extensions) == True)
