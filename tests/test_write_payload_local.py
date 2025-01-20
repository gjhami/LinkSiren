"""
This module contains tests for the `write_payload_local` function from the
`linksiren.impure_functions` module.

The tests cover the following scenarios:
- Successful writing of a text payload to a .txt file.
- Successful writing of a binary payload to a .lnk file.
- Failure to write a text payload to a .txt file due to an exception.
- Failure to write a binary payload to a .lnk file due to an exception.

Fixtures:
- `payload_name_txt`: Provides the name of the text payload file.
- `payload_name_lnk`: Provides the name of the binary payload file.
- `payload_contents`: Provides the contents of the payload.

Test Functions:
- `test_write_payload_local_txt_success`: Tests successful writing of a text payload to a .txt file.
- `test_write_payload_local_lnk_success`: Tests successful writing of a binary payload to a .lnk
    file.
- `test_write_payload_local_txt_failure`: Tests failure to write a text payload to a .txt file due
    to an exception.
- `test_write_payload_local_lnk_failure`: Tests failure to write a binary payload to a .lnk file
    due to an exception.
"""

import pytest
from linksiren.impure_functions import write_payload_local


@pytest.fixture
def payload_name_txt():
    """
    Returns the name of the payload file.

    Returns:
        str: The name of the payload file, "test_payload.txt".
    """
    return "test_payload.txt"


@pytest.fixture
def payload_name_lnk():
    """
    Returns the name of the payload link file.

    Returns:
        str: The name of the payload link file, "test_payload.lnk".
    """
    return "test_payload.lnk"


@pytest.fixture
def payload_contents():
    """
    Generates the contents of a test payload.

    Returns:
        str: A string representing the test payload.
    """
    return "This is a test payload."


def test_write_payload_local_txt_success(payload_name_txt, payload_contents, tmp_path):
    """
    Test the write_payload_local function for successful writing of a text payload.

    Args:
        payload_name_txt (str): The name of the payload file.
        payload_contents (str): The contents to be written to the payload file.
        tmp_path (pathlib.Path): A temporary directory path provided by pytest.

    Asserts:
        bool: The function returns True indicating success.
        bool: The payload file exists at the specified path.
        str: The contents of the payload file match the expected payload contents.
    """
    payload_path = tmp_path / payload_name_txt
    result = write_payload_local(str(payload_path), payload_contents)
    assert result is True
    assert payload_path.exists()
    assert payload_path.read_text() == payload_contents


def test_write_payload_local_lnk_success(payload_name_lnk, payload_contents, tmp_path):
    """
    Test the successful writing of a payload to a local link file.

    Args:
        payload_name_lnk (str): The name of the payload link file.
        payload_contents (str): The contents to be written to the payload link file.
        tmp_path (pathlib.Path): A temporary directory path provided by pytest.

    Asserts:
        bool: The result of the write_payload_local function is True.
        bool: The payload link file exists at the specified path.
        bytes: The contents of the payload link file match the expected payload contents.
    """
    payload_path = tmp_path / payload_name_lnk
    result = write_payload_local(str(payload_path), payload_contents.encode())
    assert result is True
    assert payload_path.exists()
    assert payload_path.read_bytes() == payload_contents.encode()


def test_write_payload_local_txt_failure(payload_name_txt, payload_contents, tmp_path, monkeypatch):
    """
    Test the `write_payload_local` function to ensure it handles exceptions correctly when writing
    to a text file. This test uses the `monkeypatch` fixture to replace the built-in `open`
    function with a mock that raises an exception. It then verifies that the `write_payload_local`
    function returns `False` and that no file is created.

    Args:
        payload_name_txt (str): The name of the payload file.
        payload_contents (str): The contents to be written to the payload file.
        tmp_path (pathlib.Path): A temporary directory path provided by pytest.
        monkeypatch (pytest.MonkeyPatch): A pytest fixture for safely patching and restoring
            objects.
    """

    def mock_open(*args, **kwargs):
        raise Exception("Mocked exception")

    monkeypatch.setattr("builtins.open", mock_open)
    payload_path = tmp_path / payload_name_txt
    result = write_payload_local(str(payload_path), payload_contents)
    assert result is False
    assert not payload_path.exists()


def test_write_payload_local_lnk_failure(payload_name_lnk, payload_contents, tmp_path, monkeypatch):
    """
    Test the `write_payload_local` function to ensure it handles failure when writing to a local
    file. This test simulates a failure scenario by mocking the `open` function to raise an
    exception. It verifies that the function returns `False` and that the file is not created.

    Args:
        payload_name_lnk (str): The name of the payload file.
        payload_contents (str): The contents to be written to the payload file.
        tmp_path (pathlib.Path): A temporary directory path provided by pytest.
        monkeypatch (pytest.MonkeyPatch): A pytest fixture for monkeypatching.

    Asserts:
        bool: The function should return `False` indicating failure.
        bool: The payload file should not exist.
    """

    def mock_open(*args, **kwargs):
        raise Exception("Mocked exception")

    monkeypatch.setattr("builtins.open", mock_open)
    payload_path = tmp_path / payload_name_lnk
    result = write_payload_local(str(payload_path), payload_contents.encode())
    assert result is False
    assert not payload_path.exists()
