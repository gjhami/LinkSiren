"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""
from pathlib import Path
import linksiren.pure_functions

def write_payload_local(payload_name, payload_contents):
    """
    write_payload_local(payload_name, payload_contents)

    :param str payload_name: File name, including extension, of the payload
    :param str payload_contents: Contents to write to the payload file


    :return: A bool indicateing whether or not the payload was written successfully.

    Accepts a folder path, payload name, and payload contents. Writes the supplied contents
    to the specified file and folder. Returns a bool indicating if the payload was written
    successfully.
    """
    extension = Path(payload_name).suffix

    if extension == '.lnk':
        try:  # Try to write the payload
            with open(payload_name, mode='wb') as payload_file:
                payload_file.write(payload_contents)
        except Exception as e:
            # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_name}\n{e}')
            return False
    else:
        try:  # Try to write the payload
            with open(payload_name, mode='w', newline='\r\n', encoding='utf-8') as payload_file:
                payload_file.write(payload_contents)
        except Exception as e:
            # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_name}\n\t{e}')
            return False

    # If writing the payload doesn't fail, then return True
    return True


def read_targets(targets_file):
    """
    read_targets(targets_file)

    :param str targets_file: Path to a text file containing UNC paths to file shares and base
    directories.
    :return: List of target UNC paths

    Reads in a list of targets from a specified file path and returns a list of targets.
    Catches an exception and prints an error if the targets file does not exist.
    """
    target_unc_paths = []

    # Read share targets into an array
    try:
        with open(targets_file, 'r', encoding="utf-8") as file:
            target_unc_paths = file.read().splitlines()
    except Exception as e:
        print('Error opening targets file. Make sure it exists and review its permissions.')
        print(e)

    return linksiren.pure_functions.process_targets(target_unc_paths)

# Eventually we should just pass the whole parsed arguments structure to different functions
# And then modify behaviors by checking options for things like active_threshold_date, max_depth
# creds/ntlm hash, go_fast, etc.
def get_rankings(targets, domain, username, password, active_threshold_date, max_depth, go_fast):
    """
    get_sorted_rankings(targets, active_threshold, max_depth, go_fast)

    :param list targets: List of UNC paths to shares and base directories to review.
    :param int active_threshold: Number of days within which file access constitutes a file being
    active
    :param int max_depth: Number of layers of folders to search. 1 searches only the specified
    target UNC paths and none of their subfolders.
    :param bool go_fast: If True, folders will be marked as active as soon as a single file is
    meeting the active_threshold criteria is found. A rank of 1 will be assigned to all active
    folders.

    :return: A dictionary in the format {<folder UNC path>: <ranking>} sorted by ranking

    Accepts a list of UNC paths to file shares and base directories. Gets the ranking associated
    with each folder based on the number of files active within the active_threshold number of days.
    Recursively assigns ranking to subfolders up to max_depth. If go_fast is enabled, assigns the
    rank of 1 to all folders with a single active file and moves on to the next folder. Returns a
    dirctionary of UNC paths and associated rankings. Catches exceptions for failed smb connections
    and prints a message describing the error.
    """
    # Track rankings for each folder, which are (counterintuitively) scores corresponding to the
    # number of active files in a folder. {<folder UNC path>: <ranking>}
    folder_rankings = {}

    for target in targets:
        if target.connection is None:
            try:
                target.connect(user=username, password=password, domain=domain)
            except Exception as e:
                print(f"Error connecting to {target.host}: {e}")
                return folder_rankings

        # Expand any empty paths for the target
        # An empty path indicates all shares on the host should be targeted
        try:
            target.expand_paths()
        except Exception as e:
            print(f"Error expanding paths on {target.host}: {e}")
            return folder_rankings

        try:
            # Call the appropriate review function based on the fast argument
            folder_rankings = target.review_all_folders(folder_rankings, active_threshold_date,
                                                        max_depth, go_fast)
        except Exception as e:
            print(f"Error connecting to shares on {target.host}: {e}")

    return folder_rankings


def get_sorted_rankings(targets, domain, username, password, active_threshold_date,
                        max_depth, go_fast):
    """
    Retrieve and sort rankings for given targets.
    This function fetches the rankings for the specified folders and sorts them
    based on their rankings.
    Args:
        targets (list): List of target folders to rank.
        domain (str): Domain to authenticate against.
        username (str): Username for authentication.
        password (str): Password for authentication.
        active_threshold_date (str): Date threshold to consider for active rankings.
        max_depth (int): Maximum depth to search within folders.
        go_fast (bool): Flag to enable faster processing.
    Returns:
        list: Sorted rankings of the folder UNC paths.
    """
    # Get rankings for folders
    folder_rankings = get_rankings(targets, domain, username, password, active_threshold_date,
                                   max_depth, go_fast)

    # Sort the folder UNC paths by rankings
    sorted_rankings = linksiren.pure_functions.sort_rankings(folder_rankings)
    return sorted_rankings


def write_list_to_file(input_list, file_path, mode='w'):
    """
    write_list_to_file(list, file_path)

    :param list list: A list
    :param str file_path: Path to a file to which to write
    :param str mode: String indicating the mode in which to open the output file.
    Defaults to 'w' for write.

    Writes items in a list to a specified file, one per line.
    """
    with open(file_path, mode=mode, encoding="utf-8") as f:
        for item in input_list:
            f.write(item + '\n')


def get_lnk_template(template_path):
    """
    Reads a binary file from the given template path and returns its content as a list of bytes.
    Args:
        template_path (str): The path to the binary file to be read.
    Returns:
        list: A list of bytes representing the content of the binary file.
    """
    with open(template_path, 'rb') as lnk:
        shortcut = list(lnk.read())

    return shortcut
