import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from linksiren.target import HostTarget
from impacket.smbconnection import SessionError
from impacket.nt_errors import STATUS_WRONG_PASSWORD, STATUS_CONNECTION_RESET


@pytest.fixture
def smb_connection_mock():
    connection = MagicMock()
    connection.listPath = MagicMock()
    connection.login = MagicMock()
    yield connection

@pytest.fixture(scope="function")
def host_target(smb_connection_mock):
    yield HostTarget(host="test_host", connection=smb_connection_mock)

def test_init_with_connection_and_no_host(smb_connection_mock):
    smb_connection_mock.getRemoteHost.return_value = "remote_host"
    host_target = HostTarget(host=None, connection=smb_connection_mock)
    assert host_target.host == "remote_host"
    smb_connection_mock.getRemoteHost.assert_called_once()

def test_init_with_connection_and_host(smb_connection_mock):
    host_target = HostTarget(host="test_host", connection=smb_connection_mock)
    assert host_target.host == "test_host"
    smb_connection_mock.getRemoteHost.assert_not_called()

def test_init_without_connection_and_host():
    host_target = HostTarget(host="test_host")
    assert host_target.host == "test_host"

def test_add_path_new_path(host_target):
    initial_paths = host_target.paths.copy()
    new_path = "new\\path"
    host_target.add_path(new_path)
    assert new_path in host_target.paths
    assert len(host_target.paths) == len(initial_paths) + 1

def test_add_path_existing_path(host_target):
    existing_path = "existing\\path"
    host_target.paths.append(existing_path)
    initial_paths = host_target.paths.copy()
    host_target.add_path(existing_path)
    assert host_target.paths == initial_paths
    assert len(host_target.paths) == len(initial_paths)

def test_connect_already_connected(host_target, smb_connection_mock):
    host_target.connection = smb_connection_mock
    host_target.connect(user='user', password='password', domain='domain')
    smb_connection_mock.login.assert_not_called()
    assert host_target.connection is smb_connection_mock
    assert host_target.logged_in is False

def test_connect_with_existing_connection_and_no_host(smb_connection_mock):
    smb_connection_mock.getRemoteHost.return_value = "remote_host"
    host_target = HostTarget(host=None, connection=smb_connection_mock)
    assert host_target.host == "remote_host"
    smb_connection_mock.getRemoteHost.assert_called_once()

def test_connect_no_connection_failure(host_target):
    host_target.connection = None
    with patch('linksiren.target.SMBConnection', side_effect=SessionError(STATUS_CONNECTION_RESET)):
        host_target.connect(user='user', password='password', domain='domain')
        assert host_target.connection is None
        assert host_target.logged_in is False

def test_connect_login_success(host_target, smb_connection_mock):
    host_target.connection = None
    with patch('linksiren.target.SMBConnection', return_value=smb_connection_mock):
        host_target.connect(user='user', password='password', domain='domain')
        smb_connection_mock.login.assert_called_once_with('user', 'password', 'domain', '', '', True)
        assert host_target.logged_in is True

def test_connect_login_failure(host_target, smb_connection_mock):
    host_target.connection = None
    smb_connection_mock.login.side_effect = SessionError(STATUS_WRONG_PASSWORD)
    with patch('linksiren.target.SMBConnection', return_value=smb_connection_mock):
        host_target.connect(user='user', password='password', domain='domain')
        smb_connection_mock.login.assert_called_once_with('user', 'password', 'domain', '', '', True)
        assert host_target.connection is None
        assert host_target.logged_in is False

def test_connect_with_existing_connection_and_host(smb_connection_mock):
    host_target = HostTarget(host="test_host", connection=smb_connection_mock)
    assert host_target.host == "test_host"
    smb_connection_mock.getRemoteHost.assert_not_called()

def test_expand_paths_no_empty_path(host_target):
    initial_paths = ["share\\folder1", "share\\folder2"]
    host_target.paths = initial_paths.copy()
    host_target.expand_paths()
    assert host_target.paths == initial_paths

def test_expand_paths_with_empty_path(host_target):
    STYPE_DISKTREE     = 0x00000000
    initial_paths = ["share\\folder1", ""]
    host_target.paths = initial_paths.copy()
    host_target.connection.listShares.return_value = [
        {'shi1_netname': 'share1\x00', 'shi1_type': STYPE_DISKTREE},
        {'shi1_netname': 'share2\x00', 'shi1_type': STYPE_DISKTREE},
        {'shi1_netname': 'IPC$\x00', 'shi1_type': 0x3},
    ]
    host_target.expand_paths()
    assert host_target.paths == ["share\\folder1", "share1", "share2"]

def test_expand_paths_with_empty_path_no_shares(host_target):
    initial_paths = ["share\\folder1", ""]
    host_target.paths = initial_paths.copy()
    host_target.connection.listShares.return_value = []
    host_target.expand_paths()
    assert host_target.paths == ["share\\folder1"]

def test_populate_shares_no_connection(host_target):
    host_target.paths = []
    host_target.connection = None
    host_target.populate_shares()
    assert host_target.paths == []

def test_populate_shares_with_shares(host_target):
    STYPE_DISKTREE = 0x00000000
    host_target.connection.listShares.return_value = [
        {'shi1_netname': 'share1\x00', 'shi1_type': STYPE_DISKTREE},
        {'shi1_netname': 'share2\x00', 'shi1_type': STYPE_DISKTREE},
        {'shi1_netname': 'IPC$\x00', 'shi1_type': 0x3},
    ]
    host_target.populate_shares()
    assert "share1" in host_target.paths
    assert "share2" in host_target.paths
    assert "IPC$" not in host_target.paths

def test_populate_shares_no_shares(host_target):
    host_target.paths = []
    host_target.connection.listShares.return_value = []
    host_target.populate_shares()
    assert host_target.paths == []

def test_populate_shares_failure(host_target, smb_connection_mock):
    host_target.paths = ["share\\folder1", ""]
    host_target.connection = smb_connection_mock
    smb_connection_mock.listShares.side_effect = SessionError(STATUS_CONNECTION_RESET)
    host_target.populate_shares()
    smb_connection_mock.listShares.assert_called_once()
    assert host_target.paths == ["share\\folder1", ""]

def test_write_payload_success(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(tree_id, "folder\\payload.txt")
    host_target.connection.writeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle, data=payload)
    host_target.connection.closeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle)
    host_target.connection.disconnectTree.assert_called_once_with(tree_id)
    assert result is True

def test_write_payload_no_folder(host_target):
    path = "share"
    payload_name = "payload.txt"
    payload = b"test payload"

    host_target.connection.connectTree.return_value = 1

    result = host_target.write_payload(path, payload_name, payload)
    host_target.connection.createFile.assert_called_once_with(1, payload_name)
    assert result is True


def test_write_payload_no_connection(host_target):
    host_target.connection = None
    result = host_target.write_payload("share\\folder", "payload.txt", b"test payload")
    assert result is None

def test_write_payload_connect_tree_failure(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"

    host_target.connection.connectTree.side_effect = Exception("Failed to connect to share")

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    assert result is False

def test_write_payload_create_file_failure(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.side_effect = Exception("Failed to create payload file")

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(tree_id, "folder\\payload.txt")
    assert result is False

def test_write_payload_write_file_failure(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle
    host_target.connection.writeFile.side_effect = Exception("Failed to write to payload file")

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(tree_id, "folder\\payload.txt")
    host_target.connection.writeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle, data=payload)
    assert result is False

def test_write_payload_close_file_failure(host_target):
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
    host_target.connection.createFile.assert_called_once_with(tree_id, "folder\\payload.txt")
    host_target.connection.writeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle, data=payload)
    host_target.connection.closeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle)
    assert result is False

def test_write_payload_disconnect_tree_failure(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload = b"test payload"
    tree_id = 1
    file_handle = 2

    host_target.connection.connectTree.return_value = tree_id
    host_target.connection.createFile.return_value = file_handle
    host_target.connection.disconnectTree.side_effect = Exception("Failed to disconnect tree")

    result = host_target.write_payload(path, payload_name, payload)

    host_target.connection.connectTree.assert_called_once_with(share="share")
    host_target.connection.createFile.assert_called_once_with(tree_id, "folder\\payload.txt")
    host_target.connection.writeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle, data=payload)
    host_target.connection.closeFile.assert_called_once_with(treeId=tree_id, fileId=file_handle)
    host_target.connection.disconnectTree.assert_called_once_with(tree_id)
    assert result is True

def test_delete_payload_no_folder(host_target):
    path = "share"
    payload_name = "payload.txt"

    result = host_target.delete_payload(path, payload_name)
    host_target.connection.deleteFile.assert_called_once_with(shareName="share", pathName=payload_name)

def test_delete_payload_success(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload_path = "folder\\payload.txt"

    host_target.delete_payload(path, payload_name)

    host_target.connection.deleteFile.assert_called_once_with(shareName="share", pathName=payload_path)

def test_delete_payload_no_connection(host_target):
    host_target.connection = None
    path = "share\\folder"
    payload_name = "payload.txt"

    result = host_target.delete_payload(path, payload_name)
    assert result is False

def test_delete_payload_failure(host_target):
    path = "share\\folder"
    payload_name = "payload.txt"
    payload_path = "folder\\payload.txt"

    host_target.connection.deleteFile.side_effect = Exception("Failed to delete payload")

    host_target.delete_payload(path, payload_name)

    host_target.connection.deleteFile.assert_called_once_with(shareName="share", pathName=payload_path)

def test_review_all_folders_no_connection(host_target):
    host_target.connection = None
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, datetime.now(), 1, False)
    assert result is None

def test_review_all_folders_no_files(host_target):
    host_target.connection.listPath.return_value = []
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, datetime.now(), 1, False)
    assert result == {'\\\\test_host\\share\\folder1': 0, '\\\\test_host\\share\\folder2': 0}

def test_review_all_folders_with_files(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    folder1_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time)
    ]
    folder2_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file3.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file4.txt", get_atime_epoch=lambda: active_time)
    ]
    folder3_contents = []

    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents, folder3_contents]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2", "share\\folder3"]
    result = host_target.review_all_folders(folder_rankings, now - timedelta(days=2), 1, False)
    assert result == {'\\\\test_host\\share\\folder1': 1, '\\\\test_host\\share\\folder2': 2, '\\\\test_host\\share\\folder3': 0}

def test_review_all_folders_with_subfolders(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    folder1_contents = [
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder1", get_atime_epoch=lambda: active_time)
    ]
    subfolder1_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time)
    ]
    folder2_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time)
    ]

    host_target.connection.listPath.side_effect = [folder1_contents, subfolder1_contents, folder2_contents]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, now - timedelta(days=2), 2, False)
    assert result == {'\\\\test_host\\share\\folder1': 0, '\\\\test_host\\share\\folder1\\subfolder1': 1, '\\\\test_host\\share\\folder2': 2}

def test_review_all_folders_fast(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    folder1_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time)
    ]
    folder2_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file3.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file4.txt", get_atime_epoch=lambda: inactive_time)
    ]

    host_target.connection.listPath.side_effect = [folder1_contents, folder2_contents]
    folder_rankings = {}
    host_target.paths = ["share\\folder1", "share\\folder2"]
    result = host_target.review_all_folders(folder_rankings, now - timedelta(days=2), 1, True)
    assert result == {'\\\\test_host\\share\\folder1': 1, '\\\\test_host\\share\\folder2': 1}

def test_review_folder_failed_listpath(host_target):
    accessed_time = datetime(2023, 1, 1, 12, 0, 0).timestamp()
    parent_folder_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: accessed_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: accessed_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder1", get_atime_epoch=lambda: accessed_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder2", get_atime_epoch=lambda: accessed_time)
    ]
    subfolder1_contents = SessionError(STATUS_CONNECTION_RESET)
    subfolder2_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: accessed_time),
    ]
    host_target.connection.listPath.side_effect = [parent_folder_contents, subfolder1_contents, subfolder2_contents]
    folder_rankings = {}
    with patch('linksiren.pure_functions.is_active_file', return_value=True):
        result = host_target.review_folder(folder_rankings, "share\\folder", datetime.now(), 3, False)

    assert host_target.connection.listPath.call_count == 3
    assert result == {'\\\\test_host\\share\\folder': 2,
                      '\\\\test_host\\share\\folder\\subfolder2': 1}

def test_review_folder_no_files(host_target):
    host_target.connection.listPath.return_value = []
    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share\\folder", datetime.now(), 1, False)
    assert result == {'\\\\test_host\\share\\folder': 0}

def test_review_folder_active_files(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    host_target.connection.listPath.return_value = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time)
    ]

    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share\\folder", now - timedelta(days=2), 1, False)
    assert result == {'\\\\test_host\\share\\folder': 1}

def test_review_folder_subfolders_no_folder_name(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    # Define the return values for the first and second calls to listPath
    # The second call will be made for the subfolder
    share_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "folder", get_atime_epoch=lambda: active_time)
    ]
    folder_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file3.txt", get_atime_epoch=lambda: active_time)
    ]

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [share_contents, folder_contents]

    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share", now - timedelta(days=2), 2, False)
    assert result == {'\\\\test_host\\share': 1, '\\\\test_host\\share\\folder': 3}


def test_review_folder_subfolders(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()

    # Define the return values for the first and second calls to listPath
    # The second call will be made for the subfolder
    parent_folder_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder", get_atime_epoch=lambda: active_time)
    ]
    subfolder_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file3.txt", get_atime_epoch=lambda: active_time)
    ]

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [parent_folder_contents, subfolder_contents]

    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share\\folder", now - timedelta(days=2), 2, False)
    assert result == {'\\\\test_host\\share\\folder': 1, '\\\\test_host\\share\\folder\\subfolder': 3}

def test_review_folder_mixed_content(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    parent_folder_contents = [
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

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [parent_folder_contents, subfolder1_contents,
                                                   subfolder2_contents, subfolder3_contents]

    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share\\folder", now - timedelta(days=2), 3, False)
    assert result == {'\\\\test_host\\share\\folder': 1,
                      '\\\\test_host\\share\\folder\\subfolder1': 0,
                      '\\\\test_host\\share\\folder\\subfolder1\\subfolder2': 0,
                      '\\\\test_host\\share\\folder\\subfolder3': 2}

def test_review_folder_fast(host_target):
    now = datetime.now()
    active_time = (now - timedelta(days=1)).timestamp()
    inactive_time = (now - timedelta(days=10)).timestamp()

    parent_folder_contents = [
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time),
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder1", get_atime_epoch=lambda: active_time),
    ]
    subfolder1_contents = [
        MagicMock(is_directory=lambda: True, get_longname=lambda: "subfolder2", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file1.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: active_time),
        MagicMock(is_directory=lambda: False, get_longname=lambda: "file2.txt", get_atime_epoch=lambda: inactive_time)
    ]
    subfolder2_contents = []

    # Set the side_effect of listPath to return different values on subsequent calls
    host_target.connection.listPath.side_effect = [parent_folder_contents, subfolder1_contents,
                                                   subfolder2_contents]

    folder_rankings = {}
    result = host_target.review_folder(folder_rankings, "share\\folder", now - timedelta(days=2), 1, True)
    assert result == {'\\\\test_host\\share\\folder': 1}