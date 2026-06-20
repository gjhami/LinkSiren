"""Tests for ``linksiren.impure_functions.get_rankings``."""

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import pytest

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


def _call_get_rankings(targets, credentials, threshold, depth, fast):
    """Thin helper so tests don't have to repeat the long arg list."""
    return get_rankings(
        targets=targets,
        credentials=credentials,
        active_threshold_date=threshold,
        max_depth=depth,
        go_fast=fast,
        log_queue=MagicMock(),
        max_concurrency=1,
        ignore_folders=["C$"],
    )


def test_get_rankings_no_connection(host_target, credentials):
    host_target.connection = None
    result = _call_get_rankings([host_target], credentials, datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_connection_failure(host_target, credentials):
    host_target.connection = None
    with patch.object(host_target, "connect", side_effect=Exception("Connection failed")):
        result = _call_get_rankings([host_target], credentials, datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_expand_paths_failure(host_target, credentials):
    with patch.object(host_target, "expand_paths", side_effect=Exception("Expand paths failed")):
        result = _call_get_rankings([host_target], credentials, datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_review_all_folders_failure(host_target, credentials):
    with patch.object(
        host_target,
        "review_all_folders",
        side_effect=Exception("Review folders failed"),
    ):
        result = _call_get_rankings([host_target], credentials, datetime.now(), 1, False)
    assert result == {}


def test_get_rankings_success(host_target, credentials):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    folder1_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        )
    ]
    folder2_contents = []
    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents]
    result = _call_get_rankings([host_target], credentials, now - timedelta(days=2), 1, False)
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder2": 0,
    }


def test_get_rankings_go_fast(host_target, credentials):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    folder1_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: inactive_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder1",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder3",
            get_atime_epoch=lambda: active_time,
        ),
    ]
    subfolder1_contents = [
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder2",
            get_atime_epoch=lambda: active_time,
        )
    ]
    subfolder2_contents = []
    subfolder3_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: inactive_time,
        ),
    ]
    folder2_contents = []

    host_target.connection.listPath.side_effect = [
        folder1_contents,
        subfolder1_contents,
        subfolder2_contents,
        subfolder3_contents,
        folder2_contents,
    ]

    result = _call_get_rankings([host_target], credentials, now - timedelta(days=2), 3, True)
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder1\\subfolder1": 0,
        "\\\\test_host\\share\\folder1\\subfolder1\\subfolder2": 0,
        "\\\\test_host\\share\\folder1\\subfolder3": 1,
        "\\\\test_host\\share\\folder2": 0,
    }
