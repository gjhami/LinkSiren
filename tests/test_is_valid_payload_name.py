"""
Unit tests for the `is_valid_payload_name` function from the `linksiren.pure_functions` module.
These tests verify the correctness of the `is_valid_payload_name` function by checking various
scenarios including empty names, names without extensions, names with valid and invalid extensions,
and names with mixed valid and invalid extensions.

Fixtures:
    available_extensions: Provides a list of valid file extensions for testing.

Test Cases:
    - test_empty_name: Verifies that an empty name is considered invalid.
    - test_no_extension: Verifies that a name without an extension is considered invalid.
    - test_valid_invalid_extension: Verifies that a name with a valid extension followed by an
        invalid extension is considered invalid.
    - test_invalid_valid_extension: Verifies that a name with an invalid extension followed by a
        valid extension is considered invalid.
    - test_invalid_extension: Verifies that a name with an entirely invalid extension is considered
        invalid.
    - test_valid_extensions: Verifies that names with valid extensions are considered valid.
"""
import pytest
from linksiren.pure_functions import is_valid_payload_name


@pytest.fixture
def available_extensions():
    """
    Returns a list of available file extensions.

    This function provides a list of file extensions that are considered valid
    for certain operations. The extensions include:
    - .searchConnector-ms
    - .library-ms
    - .url
    - .lnk

    Returns:
        list: A list of strings representing the available file extensions.
    """
    return [".searchConnector-ms", ".library-ms", ".url", ".lnk"]


def test_empty_name(available_extensions):
    """
    Test case for validating payload names with an empty string.

    This test checks if the function `is_valid_payload_name` correctly identifies
    an empty string as an invalid payload name.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function should return False when the payload name is an empty string.
    """
    assert is_valid_payload_name("", available_extensions) is False


def test_no_extension(available_extensions):
    """
    Test the is_valid_payload_name function with a payload name that has no extension.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function should return False when the payload name does not have an extension.
    """
    assert is_valid_payload_name("test", available_extensions) is False


def test_valid_invalid_extension(available_extensions):
    """
    Test the `is_valid_payload_name` function with an invalid file extension.

    This test checks if the function correctly identifies a payload name with an
    invalid extension as invalid.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function should return False for the given payload name with an invalid
        extension.
    """
    assert is_valid_payload_name("test.library-ms.urls", available_extensions) is False


def test_invalid_valid_extension(available_extensions):
    """
    Test the `is_valid_payload_name` function with an invalid file extension.

    This test checks if the function correctly identifies an invalid file extension
    from the provided list of available extensions.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function should return False for the given invalid file extension.
    """
    assert is_valid_payload_name("test.urls.library-mss", available_extensions) is False


def test_invalid_extension(available_extensions):
    """
    Test the `is_valid_payload_name` function with an invalid file extension.

    This test checks that the function correctly identifies a payload name
    with an extension that is not in the list of available extensions.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function should return False for a payload name with an invalid extension.
    """
    assert is_valid_payload_name("test.libary-mss", available_extensions) is False


def test_valid_extensions(available_extensions):
    """
    Test that the function `is_valid_payload_name` correctly identifies valid payload names
    based on the provided list of available extensions.

    Args:
        available_extensions (list): A list of valid file extensions.

    Asserts:
        The function `is_valid_payload_name` returns True for filenames with valid extensions.
    """
    for extension in available_extensions:
        filename = f"test.{extension}"
        assert is_valid_payload_name(filename, available_extensions) is True
