from linksiren.pure_functions import parse_target

def test_parse_target():
    unc_path = r"\\host1\share1\folder1"
    expected_host = "host1"
    expected_path = "share1\\folder1"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path

def test_parse_target_multiple_folders():
    unc_path = r"\\host2\share2\folder1\subfolder1"
    expected_host = "host2"
    expected_path = "share2\\folder1\\subfolder1"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path

def test_parse_target_single_folder():
    unc_path = r"\\host3\share3"
    expected_host = "host3"
    expected_path = "share3"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path

def test_parse_target_empty_path():
    unc_path = "\\\\host4\\"
    expected_host = "host4"
    expected_path = ""
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path

def test_parse_target_no_share():
    unc_path = r"\\host5"
    expected_host = "host5"
    expected_path = ""
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path