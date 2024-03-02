# Test for payload name validation
import pytest
from pathlib import Path
from linksiren.functions import is_valid_payload_name

# ToDo
# 1. copy everything in __main__.py besides the main function into a separate file called linksiren.py
# 2. Import all the relevant functions into __main__.py as necessary
# 3. Import all the relevant functions into this test using from linksiren import is_valid_payload_name

@pytest.fixture
def available_extensions():
    return ['searchConnector-ms', 'library-ms', 'url', 'lnk']

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
