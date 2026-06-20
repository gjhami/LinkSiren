"""Tests for ``linksiren.impure_functions.get_sorted_rankings``."""

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import pytest

from linksiren.impure_functions import get_sorted_rankings


@pytest.fixture
def target_mock():
    target = MagicMock()
    target.connection = None
    return target


@pytest.fixture
def targets_list(target_mock):
    return [target_mock]


def _call_sorted(targets, credentials, **overrides):
    """Common kwargs for ``get_sorted_rankings`` so tests stay short."""
    defaults = dict(
        targets=targets,
        credentials=credentials,
        active_threshold_date=datetime.now() - timedelta(days=7),
        max_depth=1,
        go_fast=False,
        log_queue=MagicMock(),
        max_concurrency=1,
        ignore_folders=["C$"],
    )
    defaults.update(overrides)
    return get_sorted_rankings(**defaults)


def test_get_sorted_rankings_no_connection(targets_list, credentials):
    with patch("linksiren.pure_functions.sort_rankings", return_value={}) as mock_sort_rankings:
        result = _call_sorted(targets_list, credentials)
        assert not result
        mock_sort_rankings.assert_called_once()


def test_get_sorted_rankings_with_connection(targets_list, credentials):
    targets_list[0].connection = MagicMock()
    targets_list[0].review_all_folders.return_value = {
        "\\\\test_host\\share\\folder": 1
    }
    with patch(
        "linksiren.pure_functions.sort_rankings",
        return_value={"\\\\test_host\\share\\folder": 1},
    ) as mock_sort_rankings:
        result = _call_sorted(targets_list, credentials)
        assert result == {"\\\\test_host\\share\\folder": 1}
        mock_sort_rankings.assert_called_once()


def test_get_sorted_rankings_expand_paths_failure(targets_list, credentials):
    targets_list[0].connection = MagicMock()
    targets_list[0].expand_paths.side_effect = Exception("Expand paths failed")
    with patch("linksiren.pure_functions.sort_rankings", return_value={}) as mock_sort_rankings:
        result = _call_sorted(targets_list, credentials)
        assert result == {}
        mock_sort_rankings.assert_called_once()


def test_get_sorted_rankings_review_all_folders_failure(targets_list, credentials):
    targets_list[0].connection = MagicMock()
    targets_list[0].review_all_folders.side_effect = Exception("Review folders failed")
    with patch("linksiren.pure_functions.sort_rankings", return_value={}) as mock_sort_rankings:
        result = _call_sorted(targets_list, credentials)
        assert result == {}
        mock_sort_rankings.assert_called_once()
