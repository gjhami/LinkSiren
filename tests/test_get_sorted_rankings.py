import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from linksiren.impure_functions import get_sorted_rankings

@pytest.fixture
def target_mock():
    target = MagicMock()
    target.connection = None
    return target

@pytest.fixture
def targets_list(target_mock):
    return [target_mock]

def test_get_sorted_rankings_no_connection(targets_list):
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    with patch('linksiren.pure_functions.sort_rankings', return_value={}) as mock_sort_rankings:
        result = get_sorted_rankings(targets_list, domain, username, password, active_threshold_date, max_depth, go_fast)
        assert result == {}
        mock_sort_rankings.assert_called_once()

def test_get_sorted_rankings_with_connection(targets_list):
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].connection = MagicMock()
    targets_list[0].review_all_folders.return_value = {'\\\\test_host\\share\\folder1': 1}

    with patch('linksiren.pure_functions.sort_rankings', return_value={'\\\\test_host\\share\\folder1': 1}) as mock_sort_rankings:
        result = get_sorted_rankings(targets_list, domain, username, password, active_threshold_date, max_depth, go_fast)
        assert result == {'\\\\test_host\\share\\folder1': 1}
        mock_sort_rankings.assert_called_once_with({'\\\\test_host\\share\\folder1': 1})

def test_get_sorted_rankings_expand_paths_failure(targets_list):
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].expand_paths.side_effect = Exception("Error expanding paths")

    with patch('linksiren.pure_functions.sort_rankings', return_value={}) as mock_sort_rankings:
        result = get_sorted_rankings(targets_list, domain, username, password, active_threshold_date, max_depth, go_fast)
        assert result == {}
        mock_sort_rankings.assert_called_once_with({})

def test_get_sorted_rankings_review_all_folders_failure(targets_list):
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    active_threshold_date = datetime.now() - timedelta(days=7)
    max_depth = 1
    go_fast = False

    targets_list[0].review_all_folders.side_effect = Exception("Error reviewing folders")

    with patch('linksiren.pure_functions.sort_rankings', return_value={}) as mock_sort_rankings:
        result = get_sorted_rankings(targets_list, domain, username, password, active_threshold_date, max_depth, go_fast)
        assert result == {}
        mock_sort_rankings.assert_called_once_with({})