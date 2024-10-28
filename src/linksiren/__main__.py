'''
Author: George Hamilton
Main module for the LinkSiren application.
This module handles different modes of operation for the LinkSiren application. It parses
command-line arguments and executes the appropriate handler based on the specified mode.
The available modes are:
If credentials are provided in the arguments, they are parsed and used in the appropriate handlers.
Functions:
    main(): Main function to handle different modes of operation for the LinkSiren application.
Usage:
    Run this module as a script to execute the main function.
'''
from impacket.examples.utils import parse_credentials
from linksiren.arg_parser import parse_args
from linksiren.mode_handlers import handle_generate, handle_rank, handle_identify, \
                                    handle_deploy, handle_cleanup

def main():
    """
    Main function to handle different modes of operation for the LinkSiren application.
    This function parses command-line arguments and executes the appropriate handler
    based on the specified mode. The available modes are:
    - 'generate': Generates necessary data or configurations.
    - 'rank': Ranks items based on specified criteria.
    - 'identify': Identifies specific elements or patterns.
    - 'deploy': Deploys the application or its components.
    - 'cleanup': Cleans up resources or temporary data.
    If credentials are provided in the arguments, they are parsed and used in the
    appropriate handlers.
    Args:
        None
    Returns:
        None
    """
    args = parse_args()
    if 'credentials' in args:
        domain, username, password = parse_credentials(args.credentials)
    else:
        domain, username, password = '', '', ''

    if args.mode == 'generate':
        handle_generate(args)
    elif args.mode == 'rank':
        handle_rank(args, domain, username, password)
    elif args.mode == 'identify':
        handle_identify(args, domain, username, password)
    elif args.mode == 'deploy':
        handle_deploy(args, domain, username, password)
    elif args.mode == 'cleanup':
        handle_cleanup(args, domain, username, password)

if __name__ == "__main__":
    main()
