import pytest
from linksiren.impure_functions import write_list_to_file


@pytest.fixture
def temp_file(tmp_path):
    return tmp_path / "test_file.txt"


def test_write_list_to_file_success(temp_file):
    input_list = ["item1", "item2", "item3"]
    write_list_to_file(input_list, temp_file)

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list


def test_write_list_to_file_append_mode(temp_file):
    input_list1 = ["item1", "item2"]
    input_list2 = ["item3", "item4"]

    write_list_to_file(input_list1, temp_file)
    write_list_to_file(input_list2, temp_file, mode="a")

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list1 + input_list2


def test_write_list_to_file_empty_list(temp_file):
    input_list = []
    write_list_to_file(input_list, temp_file)

    with open(temp_file, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    assert lines == input_list


def test_write_list_to_file_invalid_path():
    input_list = ["item1", "item2"]
    invalid_path = "/invalid/path/test_file.txt"

    with pytest.raises(OSError):
        write_list_to_file(input_list, invalid_path)
