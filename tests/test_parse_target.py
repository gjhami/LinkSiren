"""
This module contains unit tests for the `parse_target` function from the `linksiren.pure_functions`
module.

The `parse_target` function is designed to parse UNC (Universal Naming Convention) paths and
extract the host and path components. The tests in this module cover various scenarios to
ensure the function behaves as expected.

Test Cases:
- `test_parse_target`: Tests parsing a UNC path with a single folder.
- `test_parse_target_multiple_folders`: Tests parsing a UNC path with multiple nested folders.
- `test_parse_target_single_folder`: Tests parsing a UNC path with only a share folder.
- `test_parse_target_empty_path`: Tests parsing a UNC path with an empty path.
- `test_parse_target_no_share`: Tests parsing a UNC path with no share specified.
"""
from linksiren.pure_functions import parse_target


def test_parse_target():
    """
    Test the parse_target function to ensure it correctly parses a UNC path.

    The test checks if the function can accurately extract the host and path
    from a given UNC path string.

    Test case:
    - UNC path: \\\\host1\\share1\\folder1
    - Expected host: host1
    - Expected path: share1\\folder1

    Assertions:
    - The extracted host should match the expected host.
    - The extracted path should match the expected path.
    """
    unc_path = r"\\host1\share1\folder1"
    expected_host = "host1"
    expected_path = "share1\\folder1"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path


def test_parse_target_multiple_folders():
    """
    Test the parse_target function with a UNC path that includes multiple folders.

    This test verifies that the parse_target function correctly extracts the host and path
    from a UNC path string that contains multiple nested folders.

    Test case:
    - UNC path: \\\\host2\\share2\\folder1\\subfolder1
    - Expected host: host2
    - Expected path: share2\\folder1\\subfolder1

    Assertions:
    - The extracted host should match the expected host.
    - The extracted path should match the expected path.
    """
    unc_path = r"\\host2\share2\folder1\subfolder1"
    expected_host = "host2"
    expected_path = "share2\\folder1\\subfolder1"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path


def test_parse_target_single_folder():
    """
    Test the parse_target function with a single folder UNC path.

    This test checks if the parse_target function correctly extracts the host
    and path from a UNC path with a single folder.

    Test case:
    - UNC path: \\\\host3\\share3
    - Expected host: host3
    - Expected path: share3

    Asserts:
    - The extracted host matches the expected host.
    - The extracted path matches the expected path.
    """
    unc_path = r"\\host3\share3"
    expected_host = "host3"
    expected_path = "share3"
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path


def test_parse_target_empty_path():
    """
    Test the `parse_target` function with an empty UNC path.

    This test verifies that the `parse_target` function correctly parses a UNC path
    that contains only the host and no additional path information.

    Test case:
    - UNC path: "\\\\host4\\"
    - Expected host: "host4"
    - Expected path: ""

    Assertions:
    - The parsed host should match the expected host.
    - The parsed path should match the expected path.
    """
    unc_path = "\\\\host4\\"
    expected_host = "host4"
    expected_path = ""
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path


def test_parse_target_no_share():
    """
    Test the `parse_target` function with a UNC path that does not include a share.

    This test checks if the `parse_target` function correctly parses a UNC path
    that only contains the host and no share. The expected result is that the host
    is correctly identified, and the path is an empty string.

    Tested UNC path: \\host5
    Expected host: host5
    Expected path: ""
    """
    unc_path = r"\\host5"
    expected_host = "host5"
    expected_path = ""
    host, path = parse_target(unc_path)
    assert host == expected_host
    assert path == expected_path
