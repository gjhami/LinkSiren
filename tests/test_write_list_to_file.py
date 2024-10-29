"""
This module contains tests for the `write_list_to_file` function from the
`linksiren.impure_functions` module.

The tests cover the following scenarios:
- Writing a list of strings to a file successfully.
- Appending a list of strings to an existing file.
- Writing an empty list to a file.
- Handling invalid file paths gracefully.

The tests use the `pytest` framework and a temporary file fixture to ensure isolation and avoid
side effects.
"""

import pytest
from linksiren.impure_functions import write_list_to_file


@pytest.fixture
def temp_file(tmp_path):
    """
    Creates a temporary file path for testing purposes.

    Args:
        tmp_path (pathlib.Path): A temporary directory path provided by pytest's tmp_path fixture.

    Returns:
        pathlib.Path: The path to the temporary file named "test_file.txt" within the temporary
            directory.
    """
    return tmp_path / "test_file.txt"


def test_write_list_to_file_success(temp_file):
    """
    Test the write_list_to_file function to ensure it writes a list of strings to a file correctly.
    Args:
        temp_file (str): The temporary file path used for testing.
    Test Steps:
    1. Define an input list of strings.
    2. Call the write_list_to_file function with the input list and temporary file path.
    3. Open the temporary file in read mode and read its contents.
    4. Split the file contents into lines.
    5. Assert that the lines read from the file match the input list.
    """
    input_list = ["item1", "item2", "item3"]
    write_list_to_file(input_list, temp_file)

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list


def test_write_list_to_file_append_mode(temp_file):
    """
    Test the `write_list_to_file` function in append mode.
    This test verifies that when writing two lists to a file in append mode,
    the contents of the file include all items from both lists in the correct order.
    Args:
        temp_file (str): Path to a temporary file used for testing.
    Steps:
    1. Write `input_list1` to the temporary file.
    2. Append `input_list2` to the same file.
    3. Read the contents of the file and split into lines.
    4. Assert that the lines in the file match the concatenation of `input_list1` and `input_list2`.
    """
    input_list1 = ["item1", "item2"]
    input_list2 = ["item3", "item4"]

    write_list_to_file(input_list1, temp_file)
    write_list_to_file(input_list2, temp_file, mode="a")

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list1 + input_list2


def test_write_list_to_file_empty_list(temp_file):
    """
    Test the write_list_to_file function with an empty list.
    This test ensures that when an empty list is written to a file, the file
    remains empty.
    Args:
        temp_file (str): The path to a temporary file used for testing.
    Asserts:
        The content of the file is an empty list, matching the input list.
    """
    input_list = []
    write_list_to_file(input_list, temp_file)

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list


def test_write_list_to_file_invalid_path():
    """
    Test the `write_list_to_file` function with an invalid file path.
    This test verifies that the `write_list_to_file` function raises an `OSError`
    when provided with an invalid file path.

    Steps:
    1. Define an input list of strings.
    2. Define an invalid file path.
    3. Use `pytest.raises` to assert that `write_list_to_file` raises an `OSError`
        when called with the input list and invalid file path.

    Expected Result:
    An `OSError` should be raised due to the invalid file path.
    """
    input_list = ["item1", "item2"]
    invalid_path = "/invalid/path/test_file.txt"

    with pytest.raises(OSError):
        write_list_to_file(input_list, invalid_path)
