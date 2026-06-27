"""
Author: George Hamilton
Command-line interface for LinkSiren.

Builds an :mod:`argparse` parser with five subcommands. ``generate``, ``rank``,
``identify``, ``deploy``, ``cleanup``. Sharing a common set of authentication
flags via :func:`_add_auth_args`.
"""

import argparse


def _add_auth_args(subparser: argparse.ArgumentParser) -> None:
    """Add the shared password / hash / Kerberos auth flags to a subparser.

    All non-``generate`` subcommands need these flags, and keeping a single
    helper avoids drift across them.
    """
    auth_group = subparser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--anonymous",
        action="store_true",
        default=False,
        help="Attempt anonymous (NULL-session) SMB. Useful for share-enum "
        "recon against misconfigured hosts. Positional 'credentials' must be "
        "omitted when --anonymous is set.",
    )
    auth_group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes for Pass-the-Hash, format is LMHASH:NTHASH. A bare "
        "NT hash (no colon) is also accepted.",
    )
    auth_group.add_argument(
        "-no-pass",
        action="store_true",
        dest="no_pass",
        help="Do not prompt for / use the supplied password (useful with -k).",
    )
    auth_group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Credentials are pulled from the "
        "ccache file referenced by KRB5CCNAME. If a ccache lookup fails, the "
        "command-line credentials (password / -hashes / -aesKey) are used.",
    )
    auth_group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key (128- or 256-bit, hex) to use for Kerberos authentication.",
    )
    auth_group.add_argument(
        "-dc-ip",
        action="store",
        dest="dc_ip",
        metavar="ip address",
        help="IP address (or hostname) of the KDC / domain controller. If "
        "omitted, the domain portion of the supplied credentials is used.",
    )


def parse_args():
    """Parse command-line arguments for the LinkSiren CLI."""
    parser = argparse.ArgumentParser(
        description="Identify and rate folders in shares based on access frequency, deploy "
        "malicious URL files, and cleanup results."
    )

    subparsers = parser.add_subparsers(title="Modes", dest="mode")

    # Arguments for generating a payload locally
    generate_parser = subparsers.add_parser(
        "generate",
        description="Output specified payload file "
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
        description="Output identified subfolders and rankings to " "folder_rankings.txt",
    )
    rank_required_group = rank_parser.add_argument_group("Required Arguments")
    rank_required_group.add_argument(
        "credentials", nargs="?", help="[domain/]username[:password] for authentication. Omit when --anonymous is set."
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
    _add_auth_args(rank_parser)

    # Arguments for identifying and outputting UNC paths to optimal folders into which to place
    # poisoned files
    identify_parser = subparsers.add_parser(
        "identify",
        description="Identify target folders for payload distribution"
        " and output to payload_targets.txt",
    )
    identify_required_group = identify_parser.add_argument_group("Required Arguments")
    identify_required_group.add_argument(
        "credentials", nargs="?", help="[domain/]username[:password] for authentication. Omit when --anonymous is set."
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
    _add_auth_args(identify_parser)

    # Arguments for deploying poisoned files to specified locations
    deploy_parser = subparsers.add_parser(
        "deploy",
        description="Deploy payloads to all folder UNC "
        "paths listed one per line in the file specified using --targets",
    )
    deploy_required_group = deploy_parser.add_argument_group("Required Arguments")
    deploy_required_group.add_argument(
        "credentials", nargs="?", help="[domain/]username[:password] for authentication. Omit when --anonymous is set."
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
    _add_auth_args(deploy_parser)

    # Arguments for cleaning up deployed payloads when finished
    cleanup_parser = subparsers.add_parser(
        "cleanup",
        description="Delete poisoned files from folder UNC paths " "specified in --targets",
    )
    cleanup_required_group = cleanup_parser.add_argument_group("Required Arguments")
    cleanup_required_group.add_argument(
        "credentials", nargs="?", help="[domain/]username[:password] for authentication. Omit when --anonymous is set."
    )
    cleanup_parser.add_argument(
        "-t",
        "--targets",
        default="payloads_written.txt",
        help="(Default: 'payloads_written.txt') Path to a text file containing UNC "
        "paths poisoned files to clean up.",
    )
    _add_auth_args(cleanup_parser)

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        parser.exit()

    return args
