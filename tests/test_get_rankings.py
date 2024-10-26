import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from linksiren.impure_functions import get_rankings
from linksiren.target import HostTarget

@pytest.fixture
def smb_connection_mock():
    return MagicMock()

@pytest.fixture(scope="function")
def host_target(smb_connection_mock):
    target = HostTarget(host="test_host", connection=smb_connection_mock)
    target.paths = ["share\\folder1", "share\\folder2"]
    return target

def test_get_rankings_no_connection(host_target):
    host_target.connection = None
    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}

def test_get_rankings_connection_failure(host_target):
    host_target.connection = None
    targets = [host_target]
    with patch.object(host_target, 'connect', side_effect=Exception("Connection failed")):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}

def test_get_rankings_expand_paths_failure(host_target):
    targets = [host_target]
    with patch.object(host_target, 'expand_paths', side_effect=Exception("Expand paths failed")):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}

def test_get_rankings_review_all_folders_failure(host_target):
    targets = [host_target]
    with patch.object(host_target, 'review_all_folders', side_effect=Exception("Review folders failed")):
        result = get_rankings(targets, "domain", "user", "password", datetime.now(), 1, False)
    assert result == {}

def test_get_rankings_success(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    folder1_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time)
    ]
    folder2_contents = []
    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents]
    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", now - timedelta(days=2), 1, False)
    assert result == {'\\\\test_host\\share\\folder1': 1, '\\\\test_host\\share\\folder2': 0}

def test_get_rankings_go_fast(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    folder1_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder1", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder3", get_atime_epoch=lambda: active_time)
    ]
    subfolder1_contents = [
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder2", get_atime_epoch=lambda: active_time)
    ]
    subfolder2_contents = []
    subfolder3_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time)
    ]
    folder2_contents = []

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [folder1_contents, subfolder1_contents,
                                                   subfolder2_contents, subfolder3_contents,
                                                   folder2_contents]

    targets = [host_target]
    result = get_rankings(targets, "domain", "user", "password", now - timedelta(days=2), 3, True)
    assert result == {'\\\\test_host\\share\\folder1': 1,
                      '\\\\test_host\\share\\folder1\\subfolder1': 0,
                      '\\\\test_host\\share\\folder1\\subfolder1\\subfolder2': 0,
                      '\\\\test_host\\share\\folder1\\subfolder3': 1,
                      '\\\\test_host\\share\\folder2': 0}