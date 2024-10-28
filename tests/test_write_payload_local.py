import pytest
from linksiren.impure_functions import write_payload_local


@pytest.fixture
def payload_name_txt():
    return "test_payload.txt"


@pytest.fixture
def payload_name_lnk():
    return "test_payload.lnk"


@pytest.fixture
def payload_contents():
    return "This is a test payload."


def test_write_payload_local_txt_success(payload_name_txt, payload_contents, tmp_path):
    payload_path = tmp_path / payload_name_txt
    result = write_payload_local(str(payload_path), payload_contents)
    assert result is True
    assert payload_path.exists()
    assert payload_path.read_text() == payload_contents


def test_write_payload_local_lnk_success(payload_name_lnk, payload_contents, tmp_path):
    payload_path = tmp_path / payload_name_lnk
    result = write_payload_local(str(payload_path), payload_contents.encode())
    assert result is True
    assert payload_path.exists()
    assert payload_path.read_bytes() == payload_contents.encode()


def test_write_payload_local_txt_failure(
    payload_name_txt, payload_contents, tmp_path, monkeypatch
):
    def mock_open(*args, **kwargs):
        raise Exception("Mocked exception")

    monkeypatch.setattr("builtins.open", mock_open)
    payload_path = tmp_path / payload_name_txt
    result = write_payload_local(str(payload_path), payload_contents)
    assert result is False
    assert not payload_path.exists()


def test_write_payload_local_lnk_failure(
    payload_name_lnk, payload_contents, tmp_path, monkeypatch
):
    def mock_open(*args, **kwargs):
        raise Exception("Mocked exception")

    monkeypatch.setattr("builtins.open", mock_open)
    payload_path = tmp_path / payload_name_lnk
    result = write_payload_local(str(payload_path), payload_contents.encode())
    assert result is False
    assert not payload_path.exists()
