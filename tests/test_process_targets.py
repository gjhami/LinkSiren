import pytest
from linksiren.target import HostTarget
from linksiren.pure_functions import process_targets

@pytest.fixture
def unc_paths():
    return [
        r"\\host1\share1\folder1",
        r"\\host1\share1\folder2",
        r"\\host2\share2\folder1",
        r"\\host3\share3\folder1",
        r"\\host3\share3\folder2",
        r"\\host3\share3\folder3"
    ]

@pytest.fixture
def expected_targets():
    return [
        HostTarget(host="host1", paths=["share1\\folder1", "share1\\folder2"]),
        HostTarget(host="host2", paths=["share2\\folder1"]),
        HostTarget(host="host3", paths=["share3\\folder1", "share3\\folder2", "share3\\folder3"])
    ]

def test_process_targets(unc_paths, expected_targets):
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)

def test_process_targets_empty():
    targets = process_targets([])
    assert targets == []

def test_process_targets_single_path():
    unc_paths = [r"\\host1\share1\folder1"]
    expected_targets = [HostTarget(host="host1", paths=["share1\\folder1"])]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)

def test_process_targets_multiple_hosts():
    unc_paths = [r"\\host1\share1\folder1", r"\\host2\share2\folder1"]
    expected_targets = [
        HostTarget(host="host1", paths=["share1\\folder1"]),
        HostTarget(host="host2", paths=["share2\\folder1"])
    ]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)

def test_process_targets_duplicate_paths():
    unc_paths = [r"\\host1\share1\folder1", r"\\host1\share1\folder1"]
    expected_targets = [HostTarget(host="host1", paths=["share1\\folder1"])]
    targets = process_targets(unc_paths)
    assert len(targets) == len(expected_targets)
    for target, expected_target in zip(targets, expected_targets):
        assert target.host == expected_target.host
        assert sorted(target.paths) == sorted(expected_target.paths)