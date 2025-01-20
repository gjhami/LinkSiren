"""
Author: George Hamilton
This module provides a command-line interface (CLI) for identifying and rating folders in shares
based on access frequency, deploying malicious URL files, and cleaning up results.
Functions:
    parse_args(): Parses command-line arguments and returns them as a namespace object.
The CLI supports the following modes:
    - generate: Outputs the specified payload file to the current directory instead of a remote
                location.
    - rank: Outputs identified subfolders and rankings to folder_rankings.txt.
    - identify: Identifies target folders for payload distribution and outputs to
                payload.txt.
    - deploy: Deploys payloads to all folder UNC paths listed in the specified file.
    - cleanup: Deletes poisoned files from folder UNC paths specified in the targets file.
Each mode has its own set of required and optional arguments, which are detailed in the help
message for each subcommand.
"""

import argparse


def parse_args():
    """
    Parses command-line arguments for the LinkSiren tool.
    The tool supports multiple modes of operation, each with its own set of arguments:
    - generate: Output specified payload file to the current directory instead of a remote location.
    - rank: Output identified subfolders and rankings to folder_rankings.txt.
    - identify: Identify target folders for payload distribution and output to payload_targets.txt.
    - deploy: Deploy payloads to all folder UNC paths listed in the specified file.
    - cleanup: Delete poisoned files from folder UNC paths specified in the targets file.
    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Identify and rate folders in shares based on access frequency, deploy "
        "malicious URL files, and cleanup results."
    )

    subparsers = parser.add_subparsers(title="Modes", dest="mode")

    # Arguments for generating a payload locally
    generate_parser = subparsers.add_parser(
        "generate",
        help="Output specified payload file "
        "to the current directory instead of a remote location.",
    )
    generate_required_group = generate_parser.add_argument_group("Required Arguments")
    generate_required_group.add_argument(
        "-a",
        "--attacker",
        required=True,
        help="Attacker IP or hostname to place in malicious URL",
    )
    generate_parser.add_argument(
        "-n",
        "--payload",
        default="@Test_Do_Not_Remove.searchConnector-ms",
        help="(Default: @Test_Do_Not_Remove.searchConnector-ms) Name "
        "of payload file ending in .library-ms, .searchConnector-ms,"
        " .lnk, or .url",
    )

    # Arguments for outputting rankings of potential folders into which to place poisoned files
    rank_parser = subparsers.add_parser(
        "rank",
        help="Output identified subfolders and rankings to " "folder_rankings.txt",
    )
    rank_required_group = rank_parser.add_argument_group("Required Arguments")
    rank_required_group.add_argument(
        "credentials", help="[domain/]username[:password] for authentication"
    )
    rank_required_group.add_argument(
        "-t",
        "--targets",
        required=True,
        help="Path to a text file containing UNC "
        "paths to file shares / base directories within which to rank "
        "folders as potential locations for placing poisoned files.",
    )
    rank_parser.add_argument(
        "-md",
        "--max-depth",
        type=int,
        default=3,
        help="(Default: 3) The maximum depth of folders to search within " "the target.",
    )
    rank_parser.add_argument(
        "-at",
        "--active-threshold",
        type=int,
        default=2,
        help="(Default: 2) Number of days as an integer for active files.",
    )
    rank_parser.add_argument(
        "-f",
        "--fast",
        action="store_true",
        default=False,
        help="(Default: False) Mark folders active as soon as one active "
        "file in them is identified and move on. Ranks are all set to 1 "
        "assigned.",
    )
    rank_parser.add_argument(
        "-is",
        "--ignore-shares",
        nargs="+",
        default=["C$", "ADMIN$", "SYSVOL"],
        help="(Default: 'C$' 'ADMIN$' 'SYSVOL') Do not review the "
        "contents of specified shares when crawling as part of the folder "
        "ranking process.",
    )
    rank_parser.add_argument(
        "-mc",
        "--max-concurrency",
        type=int,
        default=4,
        help="(Default: 4) Max number of concurrent processes to use for "
        "crawling in rank and identification modes. Note: a maximum of 1 "
        "process is used per host. So linksiren will never make multiple "
        "simultaneous connections to the same host and concurrent processing "
        "will not accelerate crawling multiple shares on a single host.",
    )
    # rank_parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH",
    #                               help='NTLM hashes, format is LMHASH:NTHASH')
    # rank_parser.add_argument('-no-pass', action="store_true",
    #                               help='don\'t ask for password (useful for -k)')
    # rank_parser.add_argument('-k', action="store_true",
    #                               help='Use Kerberos authentication. Grabs credentials from
    #                               'ccache file  (KRB5CCNAME) based on target parameters. If '
    #                               'valid credentials cannot be found, it will use the ones '
    #                               'specified in the command line')
    # rank_parser.add_argument('-aesKey', action="store", metavar = "hex key",
    #                               help='AES key to use for Kerberos Authentication '
    #                               '(128 or 256 bits)')
    # rank_parser.add_argument('-keytab', action="store",
    #                               help='Read keys for SPN from keytab file')
    # rank_parser.add_argument_group('connection')
    # rank_parser.add_argument('-dc-ip', action='store',metavar = "ip address",
    #                               help='IP Address of the domain controller. If ommited it use'
    #                               'the domain part (FQDN) specified in the target parameter')

    # Arguments for identifying and outputting UNC paths to optimal folders into which to place
    # poisoned files
    identify_parser = subparsers.add_parser(
        "identify",
        help="Identify target folders for payload distribution"
        " and output to payload_targets.txt",
    )
    identify_required_group = identify_parser.add_argument_group("Required Arguments")
    identify_required_group.add_argument(
        "credentials", help="[domain/]username[:password] for authentication"
    )
    identify_required_group.add_argument(
        "-t",
        "--targets",
        required=True,
        help="Path to a text file containing "
        "UNC paths to file shares / base directories to crawl for optimal "
        "locations to write poisoned files.",
    )
    identify_parser.add_argument(
        "-md",
        "--max-depth",
        type=int,
        default=3,
        help="(Default: 3) The maximum depth of folders to search " "within the target",
    )
    identify_parser.add_argument(
        "-at",
        "--active-threshold",
        type=int,
        default=2,
        help="(Default: 2) Max number of days since within which a file is" " considered active.",
    )
    identify_parser.add_argument(
        "-f",
        "--fast",
        action="store_true",
        default=False,
        help="(Default: False) Mark folders active as soon as one active "
        "file in them is identified and move on. Ranks are all set to 1.",
    )
    identify_parser.add_argument(
        "-is",
        "--ignore-shares",
        nargs="+",
        default=["C$", "ADMIN$", "SYSVOL"],
        help="(Default: 'C$' 'ADMIN$' 'SYSVOL') Do not review the "
        "contents of specified shares when crawling as part of the folder "
        "ranking and optimal poisoning folder identification process.",
    )
    identify_parser.add_argument(
        "-mf",
        "--max-folders-per-target",
        type=int,
        default=10,
        help="(Default: 10) Maximum number of folders to output as "
        "deployment targets per supplied target share or folder.",
    )
    identify_parser.add_argument(
        "-mc",
        "--max-concurrency",
        type=int,
        default=4,
        help="(Default: 4) Max number of concurrent processes to use for "
        "crawling in rank and identification modes. Note: a maximum of 1 "
        "process is used per host. So linksiren will never make multiple "
        "simultaneous connections to the same host and concurrent processing "
        "will not accelerate crawling multiple shares on a single host.",
    )
    # identify_parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH",
    #                               help='NTLM hashes, format is LMHASH:NTHASH')
    # identify_parser.add_argument('-no-pass', action="store_true",
    #                               help='don\'t ask for password (useful for -k)')
    # identify_parser.add_argument('-k', action="store_true",
    #                               help='Use Kerberos authentication. Grabs credentials from
    #                               'ccache file  (KRB5CCNAME) based on target parameters. If '
    #                               'valid credentials cannot be found, it will use the ones '
    #                               'specified in the command line')
    # identify_parser.add_argument('-aesKey', action="store", metavar = "hex key",
    #                               help='AES key to use for Kerberos Authentication '
    #                               '(128 or 256 bits)')
    # identify_parser.add_argument('-keytab', action="store",
    #                               help='Read keys for SPN from keytab file')
    # identify_parser.add_argument_group('connection')
    # identify_parser.add_argument('-dc-ip', action='store',metavar = "ip address",
    #                               help='IP Address of the domain controller. If ommited it use'
    #                               'the domain part (FQDN) specified in the target parameter')

    # Arguments for deploying poisoned files to specified locations
    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Deploy payloads to all folder UNC "
        "paths listed one per line in the file specified using --targets",
    )
    deploy_required_group = deploy_parser.add_argument_group("Required Arguments")
    deploy_required_group.add_argument(
        "credentials", help="[domain/]username[:password] for authentication"
    )
    deploy_required_group.add_argument(
        "-a",
        "--attacker",
        required=True,
        help="Attacker IP or hostname to place in poisoned files.",
    )
    deploy_parser.add_argument(
        "-t",
        "--targets",
        default="payload_targets.txt",
        help="(Default: 'payload_targets.txt') Path to a text file containing "
        "UNC paths to folders into which poisoned files will be deployed.",
    )
    deploy_parser.add_argument(
        "-n",
        "--payload",
        default="@Test_Do_Not_Remove.searchConnector-ms",
        help="(Default: @Test_Do_Not_Remove.searchConnector-ms) Name of "
        "payload file ending in .library-ms, .searchConnector-ms, .lnk, "
        "or .url",
    )
    # deploy_parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH",
    #                               help='NTLM hashes, format is LMHASH:NTHASH')
    # deploy_parser.add_argument('-no-pass', action="store_true",
    #                               help='don\'t ask for password (useful for -k)')
    # deploy_parser.add_argument('-k', action="store_true",
    #                               help='Use Kerberos authentication. Grabs credentials from
    #                               'ccache file  (KRB5CCNAME) based on target parameters. If '
    #                               'valid credentials cannot be found, it will use the ones '
    #                               'specified in the command line')
    # deploy_parser.add_argument('-aesKey', action="store", metavar = "hex key",
    #                               help='AES key to use for Kerberos Authentication '
    #                               '(128 or 256 bits)')
    # deploy_parser.add_argument('-keytab', action="store",
    #                               help='Read keys for SPN from keytab file')
    # deploy_parser.add_argument_group('connection')
    # deploy_parser.add_argument('-dc-ip', action='store',metavar = "ip address",
    #                               help='IP Address of the domain controller. If ommited it use'
    #                               'the domain part (FQDN) specified in the target parameter')

    # Arguments for cleaning up deployed payloads when finished
    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Delete poisoned files from folder UNC paths " "specified in --targets",
    )
    cleanup_required_group = cleanup_parser.add_argument_group("Required Arguments")
    cleanup_required_group.add_argument(
        "credentials", help="[domain/]username[:password] for authentication"
    )
    cleanup_parser.add_argument(
        "-t",
        "--targets",
        default="payloads_written.txt",
        help="(Default: 'payloads_written.txt') Path to a text file containing UNC "
        "paths poisoned files to clean up.",
    )
    # cleanup_parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH",
    #                               help='NTLM hashes, format is LMHASH:NTHASH')
    # cleanup_parser.add_argument('-no-pass', action="store_true",
    #                               help='don\'t ask for password (useful for -k)')
    # cleanup_parser.add_argument('-k', action="store_true",
    #                               help='Use Kerberos authentication. Grabs credentials from
    #                               'ccache file  (KRB5CCNAME) based on target parameters. If '
    #                               'valid credentials cannot be found, it will use the ones '
    #                               'specified in the command line')
    # cleanup_parser.add_argument('-aesKey', action="store", metavar = "hex key",
    #                               help='AES key to use for Kerberos Authentication '
    #                               '(128 or 256 bits)')
    # cleanup_parser.add_argument('-keytab', action="store",
    #                               help='Read keys for SPN from keytab file')
    # cleanup_parser.add_argument_group('connection')
    # cleanup_parser.add_argument('-dc-ip', action='store',metavar = "ip address",
    #                               help='IP Address of the domain controller. If ommited it use'
    #                               'the domain part (FQDN) specified in the target parameter')

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        parser.exit()

    return args
