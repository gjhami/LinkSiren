"""
Unit tests for the `get_lnk_template` function from the `linksiren.impure_functions` module.
This module contains the following tests:
- `test_get_lnk_template_success`: Tests that `get_lnk_template` successfully reads a vali
                                   `.lnk` file.
- `test_get_lnk_template_file_not_found`: Tests that `get_lnk_template` raises a `FileNotFoundError`
    when the specified file does not exist.
- `test_get_lnk_template_empty_file`: Tests that `get_lnk_template` returns an empty list when the
    specified `.lnk` file is empty.
- `test_get_lnk_template_binary_content`: Tests that `get_lnk_template` correctly reads binary
                                          content from a `.lnk` file.
Fixtures:
- `lnk_template_path`: Creates a temporary `.lnk` file with dummy content for testing purposes.
"""
import pytest
from pathlib import Path
from linksiren.impure_functions import get_lnk_template

@pytest.fixture
def lnk_template_path():
    """
    Creates a temporary directory and a dummy .lnk file within it.

    This function creates a directory named 'temp' in the current working directory,
    if it does not already exist. Inside this directory, it creates a file named
    'template.lnk' and writes dummy content to it.

    Returns:
        Path: The path to the created 'template.lnk' file.
    """
    temp_path = Path("./temp")
    temp_path.mkdir(parents=True, exist_ok=True)
    template_path = temp_path / "template.lnk"
    with open(template_path, 'wb') as f:
        f.write(b"dummy lnk content")
    return template_path

def test_get_lnk_template_success(lnk_template_path):
    """
    Test the `get_lnk_template` function for successful execution.

    Args:
        lnk_template_path (str): The file path to the .lnk template.

    Asserts:
        - The result is an instance of `list`.
        - The result matches the expected dummy .lnk content as a list of bytes.
    """
    result = get_lnk_template(lnk_template_path)
    assert isinstance(result, list)
    assert result == list(b"dummy lnk content")

def test_get_lnk_template_file_not_found():
    """
    Test case for get_lnk_template function when the specified template file is not found.

    This test ensures that the get_lnk_template function raises a FileNotFoundError
    when it is called with a non-existent template file.

    Raises:
        FileNotFoundError: If the specified template file does not exist.
    """
    with pytest.raises(FileNotFoundError):
        get_lnk_template("non_existent_template.lnk")

def test_get_lnk_template_empty_file(tmp_path):
    """
    Test the `get_lnk_template` function with an empty file.

    This test creates an empty `.lnk` file and verifies that the `get_lnk_template`
    function returns an empty list when processing this file.

    Args:
        tmp_path (pathlib.Path): A temporary directory path provided by pytest.

    Asserts:
        The result of `get_lnk_template` is an empty list.
    """
    empty_template_path = tmp_path / "empty_template.lnk"
    empty_template_path.touch()
    result = get_lnk_template(empty_template_path)
    assert result == []

def test_get_lnk_template_binary_content(tmp_path):
    """
    Test the `get_lnk_template` function with binary content.

    This test creates a temporary binary file with predefined binary content,
    writes the content to the file, and then verifies that the `get_lnk_template`
    function correctly reads and returns the binary content as a list of bytes.

    Args:
        tmp_path (pathlib.Path): A temporary directory path provided by pytest's
                                 tmp_path fixture for creating temporary files.

    Asserts:
        The result of `get_lnk_template` should match the predefined binary content
        converted to a list of bytes.
    """
    binary_template_path = tmp_path / "binary_template.lnk"
    binary_content = b'\x00\x01\x02\x03\x04\x05'
    with open(binary_template_path, 'wb') as f:
        f.write(binary_content)
    result = get_lnk_template(binary_template_path)
    assert result == list(binary_content)
