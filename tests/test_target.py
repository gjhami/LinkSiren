"""
Unit tests for the HostTarget class in the linksiren.target module.
This module contains a series of unit tests for the HostTarget class, which is responsible for
managing connections to SMB hosts and performing various operations such as adding paths,
connecting, expanding paths, populating shares, writing payloads, deleting payloads, and
reviewing folders.

Fixtures:
    smb_connection_mock: A mock SMB connection object.
    host_target: A fixture that provides an instance of HostTarget with a mock SMB connection.

Test Cases:
    - test_init_with_connection_and_no_host: Tests initialization with a connection and no host.
    - test_init_with_connection_and_host: Tests initialization with a connection and a host.
    - test_init_without_connection_and_host: Tests initialization without a connection and with a
        host.
    - test_add_path_new_path: Tests adding a new path to the HostTarget instance.
    - test_add_path_existing_path: Tests adding an existing path to the HostTarget instance.
    - test_connect_already_connected: Tests connecting when already connected.
    - test_connect_with_existing_connection_and_no_host: Tests connecting with an existing
        connection and no host.
    - test_connect_no_connection_failure: Tests connection failure when no connection is available.
    - test_connect_login_success: Tests successful login during connection.
    - test_connect_login_failure: Tests login failure during connection.
    - test_connect_with_existing_connection_and_host: Tests connecting with an existing connection
        and host.
    - test_expand_paths_no_empty_path: Tests expanding paths when there are no empty paths.
    - test_expand_paths_with_empty_path: Tests expanding paths when there is an empty path.
    - test_expand_paths_with_empty_path_no_shares: Tests expanding paths when there is an empty
        path and no shares.
    - test_populate_shares_no_connection: Tests populating shares when there is no connection.
    - test_populate_shares_with_shares: Tests populating shares when shares are available.
    - test_populate_shares_no_shares: Tests populating shares when no shares are available.
    - test_populate_shares_failure: Tests failure during share population.
    - test_write_payload_success: Tests successful payload writing.
    - test_write_payload_no_folder: Tests payload writing when no folder is specified.
    - test_write_payload_no_connection: Tests payload writing when there is no connection.
    - test_write_payload_connect_tree_failure: Tests failure during tree connection for payload
        writing.
    - test_write_payload_create_file_failure: Tests failure during file creation for payload
        writing.
    - test_write_payload_write_file_failure: Tests failure during file writing for payload writing.
    - test_write_payload_close_file_failure: Tests failure during file closing for payload writing.
    - test_write_payload_disconnect_tree_failure: Tests failure during tree disconnection for
        payload writing.
    - test_delete_payload_no_folder: Tests payload deletion when no folder is specified.
    - test_delete_payload_success: Tests successful payload deletion.
    - test_delete_payload_no_connection: Tests payload deletion when there is no connection.
    - test_delete_payload_failure: Tests failure during payload deletion.
    - test_review_all_folders_no_connection: Tests folder review when there is no connection.
    - test_review_all_folders_no_files: Tests folder review when there are no files.
    - test_review_all_folders_with_files: Tests folder review when there are files.
    - test_review_all_folders_with_subfolders: Tests folder review when there are subfolders.
    - test_review_all_folders_fast: Tests fast folder review.
    - test_review_folder_failed_listpath: Tests folder review when listPath fails.
    - test_review_folder_no_files: Tests folder review when there are no files.
    - test_review_folder_active_files: Tests folder review when there are active files.
    - test_review_folder_subfolders_no_folder_name: Tests folder review with subfolders and no
        folder name.
    - test_review_folder_subfolders: Tests folder review with subfolders.
    - test_review_folder_mixed_content: Tests folder review with mixed content.
    - test_review_folder_fast: Tests fast folder review.
"""

from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import pytest
from impacket.smbconnection import SessionError
from impacket.nt_errors import STATUS_WRONG_PASSWORD, STATUS_CONNECTION_RESET
from impacket.dcerpc.v5.srvs import STYPE_DISKTREE
from linksiren.target import HostTarget


@pytest.fixture
def smb_connection_mock():
    """
    Mock for an SMB connection.

    This mock simulates an SMB connection with the following mocked methods:
    - `listPath`: A mocked method to simulate listing paths on the SMB server.
    - `login`: A mocked method to simulate logging into the SMB server.

    Yields:
        MagicMock: A mock object representing the SMB connection.
    """
    connection = MagicMock()
    connection.listPath = MagicMock()
    connection.login = MagicMock()
    yield connection


@pytest.fixture(scope="function")
def host_target(smb_connection_mock):
    """
    A fixture that yields a HostTarget instance with a specified host and SMB connection mock.

    Args:
        smb_connection_mock: A mock object representing the SMB connection.

    Yields:
        HostTarget: An instance of HostTarget initialized with the specified host and SMB
            connection mock.
    """
    yield HostTarget(host="test_host", connection=smb_connection_mock)


def test_init_with_connection_and_no_host(smb_connection_mock):
    """
    Test the initialization of HostTarget with a connection and no host provided.

    This test verifies that when a HostTarget is initialized with a connection
    object but without a host, the host is correctly set to the remote host
    retrieved from the connection object.

    Args:
        smb_connection_mock (Mock): A mock object for the SMB connection.

    Asserts:
        - The host attribute of the HostTarget instance is set to the remote host
          returned by the smb_connection_mock.
        - The getRemoteHost method of smb_connection_mock is called exactly once.
    """
    smb_connection_mock.getRemoteHost.return_value = "remote_host"
    host_target = HostTarget(host=None, connection=smb_connection_mock)
    assert host_target.host == "remote_host"
    smb_connection_mock.getRemoteHost.assert_called_once()


def test_init_with_connection_and_host(smb_connection_mock):
    """
    Test the initialization of HostTarget with a provided connection and host.

    This test ensures that when a HostTarget is initialized with a specific host and
    an SMB connection mock, the host attribute is set correctly and the
    getRemoteHost method on the SMB connection mock is not called.

    Args:
        smb_connection_mock (Mock): A mock object representing an SMB connection.

    Asserts:
        The host attribute of the HostTarget instance is set to "test_host".
        The getRemoteHost method on the smb_connection_mock is not called.
    """
    host_target = HostTarget(host="test_host", connection=smb_connection_mock)
    assert host_target.host == "test_host"
    smb_connection_mock.getRemoteHost.assert_not_called()


def test_init_without_connection_and_host():
    """
    Test the initialization of the HostTarget class without providing a connection.

    This test verifies that the HostTarget instance is correctly initialized with
    the specified host and that the host attribute is set to the expected value.

    Test Steps:
    1. Create an instance of HostTarget with the host parameter set to "test_host".
    2. Assert that the host attribute of the created instance is equal to "test_host".
    """
    host_target = HostTarget(host="test_host")
    assert host_target.host == "test_host"


def test_add_path_new_path(host_target):
    """
    Test the `add_path` method of the `host_target` object.

    This test verifies that a new path is correctly added to the `paths` attribute of the
    `host_target` object. It ensures that the new path is included in the `paths` list and that
    the length of the `paths` list increases by one.

    Args:
        host_target: An instance of the target object that has the `add_path` method and `paths`
            attribute.
    """
    initial_paths = host_target.paths.copy()
    new_path = "new\\path"
    host_target.add_path(new_path)
    assert new_path in host_target.paths
    assert len(host_target.paths) == len(initial_paths) + 1


def test_add_path_existing_path(host_target):
    """
    Test the `add_path` method of `host_target` when the path already exists.

    This test ensures that adding an existing path to `host_target` does not
    duplicate the path in the `paths` list.

    Args:
        host_target: An instance of the target host object with a `paths` attribute
                     and an `add_path` method.

    Steps:
        1. Append an existing path to `host_target.paths`.
        2. Copy the initial state of `host_target.paths`.
        3. Call the `add_path` method with the existing path.
        4. Assert that `host_target.paths` remains unchanged.
        5. Assert that the length of `host_target.paths` remains the same.
    """
    existing_path = "existing\\path"
    host_target.paths.append(existing_path)
    initial_paths = host_target.paths.copy()
    host_target.add_path(existing_path)
    assert host_target.paths == initial_paths
    assert len(host_target.paths) == len(initial_paths)


def test_connect_already_connected(host_target, smb_connection_mock):
    """
    Test that the `connect` method does not attempt to log in if the connection is already
    established.

    Args:
        host_target: The target host object to test.
        smb_connection_mock: A mock object representing the SMB connection.

    Asserts:
        - The `login` method of the SMB connection mock is not called.
        - The `connection` attribute of the host target is the same as the SMB connection mock.
        - The `logged_in` attribute of the host target is `False`.
    """
    host_target.connection = smb_connection_mock
    host_target.connect(user="user", password="password", domain="domain")
    smb_connection_mock.login.assert_not_called()
    assert host_target.connection is smb_connection_mock
    assert host_target.logged_in is False


def test_connect_with_existing_connection_and_no_host(smb_connection_mock):
    """
    Test the HostTarget initialization when an existing SMB connection is provided without a host.

    This test verifies that if the `HostTarget` is initialized with `host=None` and an existing
    SMB connection, the `host` attribute of the `HostTarget` instance is set to the remote host
    obtained from the SMB connection.

    Args:
        smb_connection_mock (Mock): A mock object representing an SMB connection.

    Asserts:
        - The `host` attribute of the `HostTarget` instance is set to the remote host.
        - The `getRemoteHost` method of the SMB connection mock is called exactly once.
    """
    smb_connection_mock.getRemoteHost.return_value = "remote_host"
    host_target = HostTarget(host=None, connection=smb_connection_mock)
    assert host_target.host == "remote_host"
    smb_connection_mock.getRemoteHost.assert_called_once()


def test_connect_no_connection_failure(host_target):
    """
    Test the `connect` method of `host_target` when there is no existing connection and a
    connection failure occurs.

    This test ensures that:
    - The `connection` attribute of `host_target` remains `None` after a connection attempt.
    - The `logged_in` attribute of `host_target` is set to `False` after a connection attempt.

    Args:
        host_target: An instance of the target host to be tested.

    Mocks:
        linksiren.target.SMBConnection: Mocked to raise a `SessionError` with
        `STATUS_CONNECTION_RESET` to simulate a connection failure.
    """
    host_target.connection = None
    with patch(
        "linksiren.target.SMBConnection",
        side_effect=SessionError(STATUS_CONNECTION_RESET),
    ):
        host_target.connect(user="user", password="password", domain="domain")
        assert host_target.connection is None
        assert host_target.logged_in is False


def test_connect_login_success(host_target, smb_connection_mock):
    """
    Test the successful login connection to the host target.

    This test verifies that the `connect` method of the `host_target` correctly
    establishes a connection using the provided user credentials and domain.
    It mocks the `SMBConnection` to ensure that the `login` method is called
    with the expected parameters and checks that the `logged_in` attribute of
    the `host_target` is set to `True` upon successful login.

    Args:
        host_target: The target host object to be tested.
        smb_connection_mock: A mock object for the SMB connection.

    Asserts:
        - The `login` method of the `smb_connection_mock` is called once with
          the correct user, password, domain, and other parameters.
        - The `logged_in` attribute of the `host_target` is `True` after the
          connection is established.
    """
    host_target.connection = None
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        host_target.connect(user="user", password="password", domain="domain")
        smb_connection_mock.login.assert_called_once_with(
            "user", "password", "domain", "", "", True
        )
        assert host_target.logged_in is True


def test_connect_login_failure(host_target, smb_connection_mock):
    """
    Test the `connect` method of `host_target` for a login failure scenario.

    This test verifies that when the `login` method of the `smb_connection_mock` raises a
    `SessionError` with `STATUS_WRONG_PASSWORD`, the `connect` method of `host_target` does not
    establish a connection and sets the `logged_in` attribute to `False`.

    Args:
        host_target: The target object whose `connect` method is being tested.
        smb_connection_mock: A mock object for the SMB connection.

    Assertions:
        - The `login` method of `smb_connection_mock` is called once with the provided user,
            password, and domain.
        - The `connection` attribute of `host_target` remains `None`.
        - The `logged_in` attribute of `host_target` is set to `False`.
    """
    host_target.connection = None
    smb_connection_mock.login.side_effect = SessionError(STATUS_WRONG_PASSWORD)
    with patch("linksiren.target.SMBConnection", return_value=smb_connection_mock):
        host_target.connect(user="user", password="password", domain="domain")
        smb_connection_mock.login.assert_called_once_with(
            "user", "password", "domain", "", "", True
        )
        assert host_target.connection is None
        assert host_target.logged_in is False


def test_connect_with_existing_connection_and_host(smb_connection_mock):
    """
    Test the HostTarget initialization with an existing SMB connection and a specified host.

    This test ensures that when a HostTarget is created with a given host and an existing
    SMB connection, the host attribute is correctly set to the provided host, and the
    getRemoteHost method on the SMB connection mock is not called.

    Args:
        smb_connection_mock (Mock): A mock object representing an SMB connection.

    Asserts:
        The host attribute of the HostTarget instance is set to "test_host".
        The getRemoteHost method on the smb_connection_mock is not called.
    """
    host_target = HostTarget(host="test_host", connection=smb_connection_mock)
    assert host_target.host == "test_host"
    smb_connection_mock.getRemoteHost.assert_not_called()


def test_expand_paths_no_empty_path(host_target):
    """
    Test that the `expand_paths` method of the `host_target` object does not modify the paths
    when they are not empty.

    Args:
        host_target: An instance of the target host object with a `paths` attribute and an
                     `expand_paths` method.

    Initial Conditions:
        - `host_target.paths` is set to a list of initial paths.

    Test Steps:
        1. Copy the initial paths to `host_target.paths`.
        2. Call the `expand_paths` method on `host_target`.
        3. Assert that `host_target.paths` remains unchanged and is equal to the initial paths.
    """
    initial_paths = ["share\\folder1", "share\\folder2"]
    host_target.paths = initial_paths.copy()
    host_target.expand_paths()
    assert host_target.paths == initial_paths


def test_expand_paths_with_empty_path(host_target):
    """
    Test the `expand_paths` method of the `host_target` object when one of the initial paths is
    empty.

    This test verifies that the `expand_paths` method correctly expands the paths by listing the
    shares from the connection and appending them to the paths list, excluding any non-disk tree
    shares.

    Args:
        host_target: A fixture representing the target host object with a connection attribute.

    Setup:
        - `initial_paths` is set to a list containing a valid path and an empty string.
        - `host_target.paths` is initialized with a copy of `initial_paths`.
        - `host_target.connection.listShares.return_value` is mocked to return a list of shares.

    Test:
        - Calls the `expand_paths` method on `host_target`.
        - Asserts that `host_target.paths` is correctly expanded to include the valid shares,
            excluding non-disk tree shares.
    """
    initial_paths = ["share\\folder1", ""]
    host_target.paths = initial_paths.copy()
    host_target.connection.listShares.return_value = [
        {"shi1_netname": "share1\x00", "shi1_type": STYPE_DISKTREE},
        {"shi1_netname": "share2\x00", "shi1_type": STYPE_DISKTREE},
        {"shi1_netname": "IPC$\x00", "shi1_type": 0x3},
    ]
    host_target.expand_paths()
    assert host_target.paths == ["share\\folder1", "share1", "share2"]


def test_expand_paths_with_empty_path_no_shares(host_target):
    """
    Test the expand_paths method of the host_target object when an empty path is included in the
    initial paths and no shares are returned.

    This test verifies that:
    - When the initial paths contain an empty string and a valid path.
    - The connection's listShares method returns an empty list.
    - The expand_paths method correctly removes the empty path and retains the valid path.

    Args:
        host_target: The target object whose expand_paths method is being tested.
    """
    initial_paths = ["share\\folder1", ""]
    host_target.paths = initial_paths.copy()
    host_target.connection.listShares.return_value = []
    host_target.expand_paths()
    assert host_target.paths == ["share\\folder1"]


def test_populate_shares_no_connection(host_target):
    """
    Test the `populate_shares` method of the `host_target` object when there is no connection.

    This test ensures that when the `host_target` object has no connection, the `populate_shares`
    method does not modify the `paths` attribute, leaving it as an empty list.

    Args:
        host_target: An instance of the target object to be tested.

    Asserts:
        The `paths` attribute of `host_target` remains an empty list after calling
        `populate_shares`.
    """
    host_target.paths = []
    host_target.connection = None
    host_target.populate_shares()
    assert host_target.paths == []


def test_populate_shares_with_shares(host_target):
    """
    Test the `populate_shares` method of the `host_target` object.

    This test verifies that the `populate_shares` method correctly populates the
    `paths` attribute of the `host_target` object with the names of shares that
    are of type `STYPE_DISKTREE` and excludes shares of other types.

    Steps:
    1. Mock the `listShares` method of the `connection` attribute of `host_target`
        to return a list of shares with different types.
    2. Call the `populate_shares` method of `host_target`.
    3. Assert that shares of type `STYPE_DISKTREE` are included in the `paths`
        attribute of `host_target`.
    4. Assert that shares of other types (e.g., IPC$) are not included in the
        `paths` attribute of `host_target`.

    Args:
         host_target: The target object whose `populate_shares` method is being tested.
    """
    host_target.connection.listShares.return_value = [
        {"shi1_netname": "share1\x00", "shi1_type": STYPE_DISKTREE},
        {"shi1_netname": "share2\x00", "shi1_type": STYPE_DISKTREE},
        {"shi1_netname": "IPC$\x00", "shi1_type": 0x3},
    ]
    host_target.populate_shares()
    assert "share1" in host_target.paths
    assert "share2" in host_target.paths
    assert "IPC$" not in host_target.paths


def test_populate_shares_no_shares(host_target):
    """
    Test the populate_shares method of the host_target object when there are no shares.

    This test ensures that when the listShares method returns an empty list, the
    populate_shares method correctly sets the host_target.paths attribute to an empty list.

    Args:
        host_target: A mock or fixture representing the target host object.
    """
    host_target.paths = []
    host_target.connection.listShares.return_value = []
    host_target.populate_shares()
    assert host_target.paths == []


def test_populate_shares_failure(host_target, smb_connection_mock):
    """
    Test the `populate_shares` method of `host_target` when there is a failure in listing shares.

    This test sets up the `host_target` with predefined paths and a mocked SMB connection.
    It simulates a failure in the `listShares` method by raising a `SessionError` with
    `STATUS_CONNECTION_RESET`. The test then verifies that `listShares` was called once
    and that the `paths` attribute of `host_target` remains unchanged.

    Args:
        host_target: The target object whose `populate_shares` method is being tested.
        smb_connection_mock: A mock object for the SMB connection.

    Raises:
        SessionError: If there is a connection reset error during the `listShares` call.
    """
    host_target.paths = ["share\\folder1", ""]
    host_target.connection = smb_connection_mock
    smb_connection_mock.listShares.side_effect = SessionError(STATUS_CONNECTION_RESET)
    host_target.populate_shares()
    smb_connection_mock.listShares.assert_called_once()
    assert host_target.paths == ["share\\folder1", ""]


def test_write_payload_success(host_target):
    """
    Test the write_payload method of the host_target object for successful execution.
    This test verifies that the write_payload method correctly performs the following steps:
    1. Connects to the specified tree.
    2. Creates a file in the specified path.
    3. Writes the given payload to the created file.
    4. Closes the file.
    5. Disconnects from the tree.

    The test mocks the connection methods and asserts that they are called with the expected
    arguments. It also checks that the write_payload method returns True upon successful execution.

    Args:
        host_target (object): The target object that contains the write_payload method and
        connection attributes.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(
        tree_id, "folder\\payload.txt"
    )
    host_target.connection.writeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle, data=payload
    )
    host_target.connection.closeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle
    )
    host_target.connection.disconnectTree.assert_called_once_with(tree_id)
    assert result is True


def test_write_payload_no_folder(host_target):
    """
    Test the `write_payload` method of the `host_target` object when the specified folder does not
    exist. This test verifies that the `write_payload` method correctly handles the scenario where
    the target folder does not exist by:
    1. Mocking the connection to return a tree ID.
    2. Calling the `write_payload` method with a specified path, payload name, and payload.
    3. Asserting that the `createFile` method is called once with the correct parameters.
    4. Asserting that the `write_payload` method returns `True`.

    Args:
        host_target (Mock): A mock object representing the target host with a connection attribute.
    """
    path = "share"
    payload_name = "payload.txt"
    payload = b"test payload"

    host_target.connection.connectTree.return_value = 1

    result = host_target.write_payload(path, payload_name, payload)
    host_target.connection.createFile.assert_called_once_with(1, payload_name)
    assert result is True


def test_write_payload_no_connection(host_target):
    """
    Test the write_payload method when there is no connection.

    This test sets the connection attribute of the host_target to None and
    attempts to write a payload. It asserts that the result is None, indicating
    that the write operation did not proceed due to the lack of a connection.

    Args:
        host_target: An instance of the target host object with a write_payload method.
    """
    host_target.connection = None
    result = host_target.write_payload("share\\folder", "payload.txt", b"test payload")
    assert result is None


def test_write_payload_connect_tree_failure(host_target):
    """
    Test the write_payload method of the host_target object when the connection
    to the tree fails.
    This test simulates a failure in the connectTree method of the connection
    object within host_target. It verifies that the write_payload method
    handles the exception correctly and returns False.

    Args:
        host_target: A mock or fixture representing the target host object.

    Asserts:
        - The connectTree method is called once with the correct share name.
        - The write_payload method returns False when connectTree raises an
          exception.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"

    host_target.connection.connectTree.side_effect = Exception(
        "Failed to connect to share"
    )

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    assert result is False


def test_write_payload_create_file_failure(host_target):
    """
    Test the `write_payload` method of `host_target` when creating the payload file fails.
    This test simulates a failure scenario where the `createFile` method of the
    `host_target.connection` raises an exception, indicating that the payload file could not be
    created. The test verifies that:
    1. The `connectTree` method is called once with the correct share name.
    2. The `createFile` method is called once with the correct tree ID and file path.
    3. The `write_payload` method returns `False` when the file creation fails.

    Args:
        host_target: A mock or fixture representing the target host object with a `write_payload`
        method.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.side_effect = Exception(
        "Failed to create payload file"
    )

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(
        tree_id, "folder\\payload.txt"
    )
    assert result is False


def test_write_payload_write_file_failure(host_target):
    """
    Test the `write_payload` method of `host_target` when writing to the file fails.
    This test simulates a failure scenario where the `writeFile` method raises an
    exception, and verifies that the `write_payload` method handles the exception
    correctly and returns `False`.

    Steps:
    1. Mock the `connectTree` method to return a tree ID.
    2. Mock the `createFile` method to return a file handle.
    3. Set the `writeFile` method to raise an exception.
    4. Call the `write_payload` method with the specified path, payload name, and payload.
    5. Verify that the `connectTree`, `createFile`, and `writeFile` methods are called with the
        correct arguments.
    6. Assert that the `write_payload` method returns `False`.

    Args:
        host_target: The target object whose `write_payload` method is being tested.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle
    host_target.connection.writeFile.side_effect = Exception(
        "Failed to write to payload file"
    )

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(
        tree_id, "folder\\payload.txt"
    )
    host_target.connection.writeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle, data=payload
    )
    assert result is False


def test_write_payload_close_file_failure(host_target):
    """
    Test the `write_payload` method of the `host_target` object when closing the file fails.
    This test simulates a scenario where the `closeFile` method raises an exception,
    indicating a failure to close the file after writing the payload. The test verifies
    that the `write_payload` method handles this exception correctly and returns `False`.

    Steps:
    1. Mock the `connectTree` method to return a tree ID.
    2. Mock the `createFile` method to return a file handle.
    3. Set the `closeFile` method to raise an exception.
    4. Call the `write_payload` method with a specified path, payload name, and payload.
    5. Assert that the `connectTree`, `createFile`, `writeFile`, and `closeFile` methods
        are called with the expected arguments.
    6. Assert that the `write_payload` method returns `False` when `closeFile` fails.

    Args:
         host_target (object): The target object whose `write_payload` method is being tested.

    Asserts:
         - `connectTree` is called once with the correct share name.
         - `createFile` is called once with the correct tree ID and file path.
         - `writeFile` is called once with the correct tree ID, file handle, and payload data.
         - `closeFile` is called once with the correct tree ID and file handle.
         - The `write_payload` method returns `False` when `closeFile` raises an exception.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle
    host_target.connection.closeFile.side_effect = Exception("Failed to close file")

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(
        tree_id, "folder\\payload.txt"
    )
    host_target.connection.writeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle, data=payload
    )
    host_target.connection.closeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle
    )
    assert result is False


def test_write_payload_disconnect_tree_failure(host_target):
    """
    Test the `write_payload` method of `host_target` when disconnecting from the tree fails.
    This test simulates a scenario where the `disconnectTree` method raises an exception.
    It verifies that the `write_payload` method correctly handles the failure and still
    returns `True`.

    Steps:
    1. Mock the `connectTree` method to return a tree ID of 1.
    2. Mock the `createFile` method to return a file handle of 2.
    3. Set the `disconnectTree` method to raise an exception with the message "Failed to disconnect
        tree".
    4. Call the `write_payload` method with the specified path, payload name, and payload.
    5. Verify that the `connectTree` method was called once with the correct share.
    6. Verify that the `createFile` method was called once with the correct tree ID and file path.
    7. Verify that the `writeFile` method was called once with the correct tree ID, file handle,
        and data.
    8. Verify that the `closeFile` method was called once with the correct tree ID and file handle.
    9. Verify that the `disconnectTree` method was called once with the correct tree ID.
    10. Assert that the result of the `write_payload` method is `True`.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle
    host_target.connection.disconnectTree.side_effect = Exception(
        "Failed to disconnect tree"
    )

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(
        tree_id, "folder\\payload.txt"
    )
    host_target.connection.writeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle, data=payload
    )
    host_target.connection.closeFile.assert_called_once_with(
        treeId=tree_id, fileId=file_handle
    )
    host_target.connection.disconnectTree.assert_called_once_with(tree_id)
    assert result is True


def test_delete_payload_no_folder(host_target):
    """
    Test the `delete_payload` method of `host_target` when no folder is specified.
    This test verifies that the `delete_payload` method correctly calls the
    `deleteFile` method on the `connection` attribute of `host_target` with the
    expected parameters when only a payload name is provided.

    Args:
        host_target: The target object whose `delete_payload` method is being tested.

    Asserts:
        - The `deleteFile` method on `host_target.connection` is called exactly once
          with the `shareName` set to "share" and `pathName` set to "payload.txt".
    """
    path = "share"
    payload_name = "payload.txt"

    result = host_target.delete_payload(path, payload_name)
    host_target.connection.deleteFile.assert_called_once_with(
        shareName="share", pathName=payload_name
    )
    assert result is True


def test_delete_payload_success(host_target):
    """
    Test that the delete_payload method successfully deletes a payload file.

    Args:
        host_target: An instance of the target host which has the delete_payload method.

    The test verifies that the delete_payload method is called with the correct path and payload
    name, and that the connection's deleteFile method is called once with the expected share name
    and path name.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload_path = "folder\\payload.txt"

    host_target.delete_payload(path, payload_name)

    host_target.connection.deleteFile.assert_called_once_with(
        shareName="share", pathName=payload_path
    )


def test_delete_payload_no_connection(host_target):
    """
    Test the delete_payload method when there is no connection.
    This test sets the connection attribute of the host_target to None,
    simulates a scenario where the connection is unavailable, and attempts
    to delete a payload. It asserts that the delete_payload method returns
    False, indicating that the deletion was unsuccessful due to the lack
    of connection.

    Args:
        host_target: An instance of the target host object with a delete_payload method.
    """
    host_target.connection = None
    path = "share\\folder"
    payload_name = "payload.txt"

    result = host_target.delete_payload(path, payload_name)
    assert result is False


def test_delete_payload_failure(host_target):
    """
    Test the failure scenario of the delete_payload method in the host_target object.
    This test verifies that the delete_payload method correctly handles the case
    where the deletion of a payload file fails. It ensures that the deleteFile
    method of the host_target's connection is called with the correct parameters
    and that an exception is raised when the deletion fails.

    Args:
        host_target (Mock): A mock object representing the target host.

    Setup:
        - Mocks the deleteFile method of the host_target's connection to raise an
          Exception with the message "Failed to delete payload".

    Test Steps:
        1. Define the path, payload_name, and payload_path variables.
        2. Set the side effect of the deleteFile method to raise an Exception.
        3. Call the delete_payload method with the path and payload_name.
        4. Assert that the deleteFile method was called once with the correct
           shareName and pathName parameters.
    """
    path = "share\\folder"
    payload_name = "payload.txt"
    payload_path = "folder\\payload.txt"

    host_target.connection.deleteFile.side_effect = Exception(
        "Failed to delete payload"
    )

    host_target.delete_payload(path, payload_name)

    host_target.connection.deleteFile.assert_called_once_with(
        shareName="share", pathName=payload_path
    )


def test_review_all_folders_no_connection(host_target):
    """
    Test the review_all_folders method when there is no connection.

    This test sets the connection attribute of the host_target to None and
    initializes folder_rankings as an empty dictionary. It then sets the
    paths attribute of the host_target to a list of folder paths. The test
    calls the review_all_folders method with the initialized parameters and
    asserts that the result is None.

    Args:
        host_target: An instance of the target host object to be tested.
    """
    host_target.connection = None
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, datetime.now(), 1, False)
    assert result is None


def test_review_all_folders_no_files(host_target):
    """
    Test the `review_all_folders` method of the `host_target` object when there are no files in
    the folders.

    This test verifies that the `review_all_folders` method correctly handles the case where the
    folders are empty and returns the expected folder rankings.

    Args:
        host_target (Mock): A mock object representing the host target, with its
            `connection.listPath` method mocked to return an empty list.

    Setup:
        - The `host_target.paths` attribute is set to a list of folder paths.
        - The `host_target.connection.listPath` method is mocked to return an empty list,
            simulating empty folders.

    Test:
        - Calls the `review_all_folders` method with an empty `folder_rankings` dictionary, the
            current datetime, a depth of 1, and `False` for the `recursive` parameter.
        - Asserts that the result is a dictionary with the folder paths as keys and 0 as values,
            indicating no files were found in the folders.
    """
    host_target.connection.listPath.return_value = []
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, datetime.now(), 1, False)
    assert result == {
        "\\\\test_host\\share\\folder1": 0,
        "\\\\test_host\\share\\folder2": 0,
    }


def test_review_all_folders_with_files(host_target):
    """
    Test the `review_all_folders` method of the `host_target` object.
    This test verifies that the `review_all_folders` method correctly ranks folders based on the
    number of files accessed within a specified time frame.

    Args:
        host_target (MagicMock): A mock object representing the host target.

    Setup:
        - Mocks the current time and calculates active and inactive access times.
        - Creates mock folder contents with files having different access times.
        - Sets up the `listPath` method of the `host_target.connection` to return the mock folder
            contents.
        - Defines the paths for the folders to be reviewed.

    Test:
        - Calls the `review_all_folders` method with the mock folder rankings, a time threshold,
            and other parameters.
        - Asserts that the result matches the expected folder rankings based on the number of
            recently accessed files.

    Expected Result:
        The method should return a dictionary with folder paths as keys and the count of recently
        accessed files as values.
    """
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
    ]
    folder2_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file3.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file4.txt",
            get_atime_epoch=lambda: active_time,
        ),
    ]
    folder3_contents = []

    host_target.connection.listPath.side_effect = [
        folder1_contents,
        folder2_contents,
        folder3_contents,
    ]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2", "share\\folder3"]
    result = host_target.review_all_folders(
        folder_rankings, now - timedelta(days=2), 1, False
    )
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder2": 2,
        "\\\\test_host\\share\\folder3": 0,
    }


def test_review_all_folders_with_subfolders(host_target):
    """
    Test the review_all_folders method of the host_target object to ensure it correctly
    ranks folders and subfolders based on their access times.
    The test sets up a mock file structure with two folders, where the first folder contains
    a subfolder with a file, and the second folder contains two files. The access times of
    all files and folders are set to be within the active time window.

    Args:
        host_target (MagicMock): A mock object representing the host target with a connection
                                 that can list paths and review folders.

    Asserts:
        The result of the review_all_folders method matches the expected folder rankings.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    folder1_contents = [
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder1",
            get_atime_epoch=lambda: active_time,
        )
    ]
    subfolder1_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        )
    ]
    folder2_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: active_time,
        ),
    ]

    host_target.connection.listPath.side_effect = [
        folder1_contents,
        subfolder1_contents,
        folder2_contents,
    ]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(
        folder_rankings, now - timedelta(days=2), 2, False
    )
    assert result == {
        "\\\\test_host\\share\\folder1": 0,
        "\\\\test_host\\share\\folder1\\subfolder1": 1,
        "\\\\test_host\\share\\folder2": 2,
    }


def test_review_all_folders_fast(host_target):
    """
    Test the `review_all_folders` method of the `host_target` object.
    This test verifies that the `review_all_folders` method correctly ranks folders
    based on the access time of their contents. It mocks the contents of two folders
    with files having different access times and checks if the method returns the
    expected rankings.

    Args:
        host_target (MagicMock): A mock object representing the target host.

    Setup:
        - Mocks the current time and calculates active and inactive access times.
        - Creates mock folder contents with files having different access times.
        - Sets up the `listPath` method of the `host_target.connection` to return
          the mocked folder contents.
        - Sets the paths to be reviewed in the `host_target.paths`.

    Test:
        - Calls the `review_all_folders` method with the mocked data.
        - Asserts that the method returns the expected folder rankings.
    """
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
    ]
    folder2_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file3.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file4.txt",
            get_atime_epoch=lambda: inactive_time,
        ),
    ]

    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(
        folder_rankings, now - timedelta(days=2), 1, True
    )
    assert result == {
        "\\\\test_host\\share\\folder1": 1,
        "\\\\test_host\\share\\folder2": 1,
    }


def test_review_folder_failed_listpath(host_target):
    """
    Test the `review_folder` method of `host_target` when listing the contents of a folder
    results in a connection reset error for one of the subfolders.

    This test sets up a mock environment where:
    - The parent folder contains two files and two subfolders.
    - The first subfolder raises a `SessionError` with `STATUS_CONNECTION_RESET`.
    - The second subfolder contains one file.

    The test verifies that:
    - The `listPath` method is called three times (once for the parent folder and once for each
        subfolder).
    - The result of the `review_folder` method correctly reflects the number of active files in
        the parent folder and the second subfolder, while ignoring the first subfolder due to the
        connection reset error.

    Args:
        host_target (MagicMock): The mock object representing the host target.

    Asserts:
        - The `listPath` method is called three times.
        - The result of the `review_folder` method is as expected.
    """
    accessed_time = datetime(2023, 1, 1, 12, 0, 0).timestamp()
    parent_folder_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: accessed_time,
        ),
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file2.txt",
            get_atime_epoch=lambda: accessed_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder1",
            get_atime_epoch=lambda: accessed_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder2",
            get_atime_epoch=lambda: accessed_time,
        ),
    ]
    subfolder1_contents = SessionError(STATUS_CONNECTION_RESET)
    subfolder2_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: accessed_time,
        ),
    ]
    host_target.connection.listPath.side_effect = [
        parent_folder_contents,
        subfolder1_contents,
        subfolder2_contents,
    ]
    folder_rankings = {}
    with patch("linksiren.pure_functions.is_active_file", return_value=True):
        result = host_target.review_folder(
            folder_rankings, "share\\folder", datetime.now(), 3, False
        )

    assert host_target.connection.listPath.call_count == 3
    assert result == {
        "\\\\test_host\\share\\folder": 2,
        "\\\\test_host\\share\\folder\\subfolder2": 1,
    }


def test_review_folder_no_files(host_target):
    """
    Test the review_folder method when there are no files in the folder.

    This test mocks the listPath method of the host_target's connection to return an empty list,
    simulating a folder with no files. It then calls the review_folder method with the mocked data
    and checks if the result is as expected.

    Args:
        host_target: The target host object with a connection attribute that has a listPath method.

    Asserts:
        The result of the review_folder method should be a dictionary with the folder path as the
        key and 0 as the value, indicating no files were found in the folder.
    """
    host_target.connection.listPath.return_value = []
    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share\\folder", datetime.now(), 1, False
    )
    assert result == {"\\\\test_host\\share\\folder": 0}


def test_review_folder_active_files(host_target):
    """
    Test the review_folder method of the host_target object to ensure it correctly
    identifies active files within a specified time frame.
    This test sets up a mock connection to simulate a folder containing two files:
    one active and one inactive. The active file has an access time within the last
    day, while the inactive file has an access time older than 10 days.
    The review_folder method is then called with a time frame of the last 2 days
    and a threshold of 1 active file. The expected result is that the folder is
    identified as having 1 active file.

    Args:
        host_target (MagicMock): A mock object representing the host target with a
                                 connection attribute that simulates file listings.

    Asserts:
        The result of the review_folder method matches the expected dictionary
        indicating the folder has 1 active file.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    host_target.connection.listPath.return_value = [
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
    ]

    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share\\folder", now - timedelta(days=2), 1, False
    )
    assert result == {"\\\\test_host\\share\\folder": 1}


def test_review_folder_subfolders_no_folder_name(host_target):
    """
    Test the review_folder method of the host_target object when there are subfolders
    and no specific folder name is provided.
    This test simulates a scenario where the share contains both files and a subfolder,
    and the subfolder contains multiple files. The method should correctly count the
    number of files in the share and its subfolder.

    Args:
        host_target: The target object that contains the review_folder method and
                     connection attribute.

    Setup:
        - Mock the current time and calculate an active time for the files.
        - Define the return values for the listPath method to simulate the contents
          of the share and the subfolder.
        - Set the side_effect of listPath to return different values on subsequent calls.

    Assertions:
        - Verify that the result of the review_folder method matches the expected
          dictionary with the correct file counts for the share and its subfolder.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    # Define the return values for the first and second calls to listPath
    # The second call will be made for the subfolder
    share_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "folder",
            get_atime_epoch=lambda: active_time,
        ),
    ]
    folder_contents = [
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
            get_longname=lambda: "file3.txt",
            get_atime_epoch=lambda: active_time,
        ),
    ]

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [share_contents, folder_contents]

    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share", now - timedelta(days=2), 2, False
    )
    assert result == {"\\\\test_host\\share": 1, "\\\\test_host\\share\\folder": 3}


def test_review_folder_subfolders(host_target):
    """
    Test the review_folder method to ensure it correctly processes subfolders.
    This test mocks the behavior of the host_target's connection to simulate
    a folder structure with both files and subfolders. It verifies that the
    review_folder method correctly counts the number of files in both the
    parent folder and its subfolder.

    Args:
        host_target (MagicMock): A mock object representing the target host.

    Assertions:
        Asserts that the result of the review_folder method matches the expected
        dictionary with the correct file counts for the parent folder and its
        subfolder.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    # Define the return values for the first and second calls to listPath
    # The second call will be made for the subfolder
    parent_folder_contents = [
        MagicMock(
            is_directory=lambda: False,
            get_longname=lambda: "file1.txt",
            get_atime_epoch=lambda: active_time,
        ),
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder",
            get_atime_epoch=lambda: active_time,
        ),
    ]
    subfolder_contents = [
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
            get_longname=lambda: "file3.txt",
            get_atime_epoch=lambda: active_time,
        ),
    ]

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [
        parent_folder_contents,
        subfolder_contents,
    ]

    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share\\folder", now - timedelta(days=2), 2, False
    )
    assert result == {
        "\\\\test_host\\share\\folder": 1,
        "\\\\test_host\\share\\folder\\subfolder": 3,
    }


def test_review_folder_mixed_content(host_target):
    """
    Test the `review_folder` method of the `host_target` object with a mixed content folder
    structure. This test sets up a mock folder structure with both files and subfolders, some of
    which are active and some inactive. It then verifies that the `review_folder` method correctly
    ranks the folders based on the activity of their contents.

    Args:
        host_target (MagicMock): A mock object representing the target host with a connection that
        can list paths.

    Setup:
        - Creates a mock current time (`now`).
        - Defines active and inactive times for file access.
        - Sets up mock contents for a parent folder and its subfolders.
        - Configures the `listPath` method of the `host_target.connection` to return the mock
            contents in sequence.

    Test:
        - Calls the `review_folder` method with the mock folder structure and checks the resulting
            folder rankings.

    Asserts:
        - The resulting folder rankings match the expected values, indicating correct behavior of
            the `review_folder` method.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    parent_folder_contents = [
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

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [
        parent_folder_contents,
        subfolder1_contents,
        subfolder2_contents,
        subfolder3_contents,
    ]

    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share\\folder", now - timedelta(days=2), 3, False
    )
    assert result == {
        "\\\\test_host\\share\\folder": 1,
        "\\\\test_host\\share\\folder\\subfolder1": 0,
        "\\\\test_host\\share\\folder\\subfolder1\\subfolder2": 0,
        "\\\\test_host\\share\\folder\\subfolder3": 2,
    }


def test_review_folder_fast(host_target):
    """
    Test the `review_folder` method of the `host_target` object to ensure it correctly
    ranks folders based on their activity within a specified time frame.
    This test sets up a mock file structure with different access times and verifies
    that the `review_folder` method correctly identifies and ranks the active folders.

    Args:
        host_target (MagicMock): A mock object representing the target host with a
                                 `review_folder` method and a `connection` attribute
                                 that can list folder contents.

    Setup:
        - Creates mock folder contents with varying access times.
        - Configures the `listPath` method of the `host_target.connection` to return
          these mock contents in a specific order.

    Assertions:
        - Verifies that the `review_folder` method returns the correct ranking for
          the folders based on their activity within the last 2 days.
    """
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    parent_folder_contents = [
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
    ]
    subfolder1_contents = [
        MagicMock(
            is_directory=lambda: True,
            get_longname=lambda: "subfolder2",
            get_atime_epoch=lambda: active_time,
        ),
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
    subfolder2_contents = []

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [
        parent_folder_contents,
        subfolder1_contents,
        subfolder2_contents,
    ]

    folder_rankings = {}
    result = host_target.review_folder(
        folder_rankings, "share\\folder", now - timedelta(days=2), 1, True
    )
    assert result == {"\\\\test_host\\share\\folder": 1}
