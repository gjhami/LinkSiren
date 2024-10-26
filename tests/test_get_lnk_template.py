import pytest
from pathlib import Path
from linksiren.impure_functions import get_lnk_template

@pytest.fixture
def lnk_template_path(tmp_path):
    template_path = tmp_path / "template.lnk"
    with open(template_path, 'wb') as f:
        f.write(b"dummy lnk content")
    return template_path

def test_get_lnk_template_success(lnk_template_path):
    result = get_lnk_template(lnk_template_path)
    assert isinstance(result, list)
    assert result == list(b"dummy lnk content")

def test_get_lnk_template_file_not_found():
    with pytest.raises(FileNotFoundError):
        get_lnk_template("non_existent_template.lnk")

def test_get_lnk_template_empty_file(tmp_path):
    empty_template_path = tmp_path / "empty_template.lnk"
    empty_template_path.touch()
    result = get_lnk_template(empty_template_path)
    assert result == []

def test_get_lnk_template_binary_content(tmp_path):
    binary_template_path = tmp_path / "binary_template.lnk"
    binary_content = b'\x00\x01\x02\x03\x04\x05'
    with open(binary_template_path, 'wb') as f:
        f.write(binary_content)
    result = get_lnk_template(binary_template_path)
    assert result == list(binary_content)