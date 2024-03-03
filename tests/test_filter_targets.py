import pytest
from linksiren.pure_functions import filter_targets

@pytest.fixture
def sorted_rankings():
    rankings = {
        'share1\\folder1': 10,
        'share1\\folder2': 8,
        'share1\\folder3': 5,
        'share2\\folder1': 8,
        'share2\\folder2': 3,
        'share2\\folder3': 2,
        'share2\\folder4': 1,
        'share3\\folder1': 6,
        'share3\\folder2': 2,
    }

    return rankings

def test_single_target_single_folder(sorted_rankings):
    targets = ['share2']
    max_folders_per_target = 1
    expected_result = ['share2\\folder1']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result

def test_single_target_multi_folder(sorted_rankings):
    targets = ['share1']
    max_folders_per_target = 2
    expected_result = ['share1\\folder1', 'share1\\folder2']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result

def test_multi_target_single_folder(sorted_rankings):
    targets = ['share1', 'share3']
    max_folders_per_target = 1
    expected_result = ['share1\\folder1', 'share3\\folder1']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result

def test_multi_target_multi_folder(sorted_rankings):
    targets = ['share1', 'share2']
    max_folders_per_target = 3
    expected_result = ['share1\\folder1', 'share1\\folder2', 'share1\\folder3', 'share2\\folder1', 'share2\\folder2', 'share2\\folder3']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result

def test_filter_targets_empty_targets(sorted_rankings):
    max_folders_per_target = 10
    result = filter_targets([], sorted_rankings, max_folders_per_target)
    assert result == []

def test_filter_targets_empty_rankings():
    targets = ['share1', 'share2']
    max_folders_per_target = 5
    result = filter_targets(targets, {}, max_folders_per_target)
    assert result == []

def test_filter_targets_zero_max_folders(sorted_rankings):
    targets = ['share1', 'share2']
    max_folders_per_target = 0
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == []

def test_filter_targets_max_folders_greater_than_rankings(sorted_rankings):
    targets = ['share1', 'share3']
    max_folders_per_target = 10
    expected_result = ['share1\\folder1', 'share1\\folder2', 'share1\\folder3', 'share3\\folder1', 'share3\\folder2']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result
