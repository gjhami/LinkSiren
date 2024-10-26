import pytest
from linksiren.pure_functions import filter_targets
from linksiren.target import HostTarget  # Import the HostTarget class

@pytest.fixture
def sorted_rankings():
    rankings = {
        # Host 1
        '\\\\host1\\share1\\folder1': 8,
        '\\\\host1\\share1\\folder2': 9,
        '\\\\host1\\share1\\folder3': 9,
        '\\\\host1\\share2\\folder1': 10,
        '\\\\host1\\share2\\folder2': 3,
        '\\\\host1\\share2\\folder3': 2,
        '\\\\host1\\share2\\folder4': 1,
        '\\\\host1\\share3\\folder1': 6,
        '\\\\host1\\share3\\folder2': 2,

        # Host 2
        '\\\\host2\\share1\\folder1': 8,
        '\\\\host2\\share1\\folder2': 8,
        '\\\\host2\\share1\\folder3': 5,
        '\\\\host2\\share2\\folder1': 10,
        '\\\\host2\\share2\\folder2': 3,
        '\\\\host2\\share2\\folder3': 2,
        '\\\\host2\\share2\\folder4': 11,
        '\\\\host2\\share3\\folder1': 6,
        '\\\\host2\\share3\\folder2': 2,

        # Host 3
        '\\\\host3\\share1\\folder1': 8,
        '\\\\host3\\share1\\folder2': 1,
        '\\\\host3\\share1\\folder3': 5,
        '\\\\host3\\share2\\folder1': 10,
        '\\\\host3\\share2\\folder2': 3,
        '\\\\host3\\share2\\folder3': 2,
        '\\\\host3\\share2\\folder4': 1,
        '\\\\host3\\share3\\folder1': 8,
        '\\\\host3\\share3\\folder2': 2,
    }
    rankings = dict(sorted(rankings.items(), key=lambda item: item[1], reverse=True))
    return rankings

@pytest.fixture
def host_targets():
    # Create HostTarget instances
    host1 = HostTarget(host='host1', paths=['share1\\folder1', 'share1\\folder2',
                                            'share1\\folder3'])
    host2 = HostTarget(host='host2', paths=['share2\\folder1', 'share2\\folder2',
                                            'share2\\folder3', 'share2\\folder4'])
    host3 = HostTarget(host='host3', paths=['share3\\folder1', 'share3\\folder2'])
    return [host1, host2, host3]

def test_single_target_single_folder(sorted_rankings, host_targets):
    targets = [host_targets[1]]
    max_folders_per_target = 1
    expected_result = ['\\\\host2\\share2\\folder4']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == expected_result

def test_single_target_multi_folder(sorted_rankings, host_targets):
    targets = [host_targets[0]]
    max_folders_per_target = 2
    expected_result = ['\\\\host1\\share2\\folder1', '\\\\host1\\share1\\folder2']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)

def test_multi_target_single_folder(sorted_rankings, host_targets):
    targets = [host_targets[0], host_targets[2]]  # Use HostTarget instances for share1 and share3
    max_folders_per_target = 1
    expected_result = ['\\\\host1\\share2\\folder1', '\\\\host3\\share2\\folder1', ]
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)

def test_multi_target_multi_folder(sorted_rankings, host_targets):
    targets = [host_targets[0], host_targets[1]]  # Use HostTarget instances for share1 and share2
    max_folders_per_target = 3
    expected_result = ['\\\\host1\\share2\\folder1', '\\\\host1\\share1\\folder2',
                       '\\\\host1\\share1\\folder3', '\\\\host2\\share2\\folder4',
                       '\\\\host2\\share2\\folder1', '\\\\host2\\share1\\folder1']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)

def test_filter_targets_empty_targets(sorted_rankings):
    max_folders_per_target = 10
    result = filter_targets([], sorted_rankings, max_folders_per_target)
    assert result == []

def test_filter_targets_empty_rankings():
    targets = ['share1', 'share2']
    max_folders_per_target = 5
    result = filter_targets(targets, {}, max_folders_per_target)
    assert result == []

def test_filter_targets_zero_max_folders(sorted_rankings, host_targets):
    targets = [host_targets[0], host_targets[1]]  # Use HostTarget instances for share1 and share2
    max_folders_per_target = 0
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == []

def test_filter_targets_max_folders_greater_than_rankings(sorted_rankings, host_targets):
    targets = [host_targets[0], host_targets[2]]  # Use HostTarget instances for share1 and share3
    max_folders_per_target = 10
    expected_result = ['\\\\host1\\share1\\folder1', '\\\\host1\\share1\\folder2',
                       '\\\\host1\\share1\\folder3', '\\\\host1\\share2\\folder1',
                       '\\\\host1\\share2\\folder2', '\\\\host1\\share2\\folder3',
                       '\\\\host1\\share2\\folder4', '\\\\host1\\share3\\folder1',
                       '\\\\host1\\share3\\folder2', '\\\\host3\\share1\\folder1',
                       '\\\\host3\\share1\\folder2', '\\\\host3\\share1\\folder3',
                       '\\\\host3\\share2\\folder1', '\\\\host3\\share2\\folder2',
                       '\\\\host3\\share2\\folder3', '\\\\host3\\share2\\folder4',
                       '\\\\host3\\share3\\folder1', '\\\\host3\\share3\\folder2']
    result = filter_targets(targets, sorted_rankings, max_folders_per_target)
    assert result == sorted(expected_result)
