"""
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
"""

from dataclasses import dataclass
from multiprocessing import Manager
from impacket.examples.utils import parse_credentials
from linksiren.arg_parser import parse_args
from linksiren.logging_config import (
    configure_main_logger,
    configure_queue_listener,
)
from linksiren.mode_handlers import (
    handle_generate,
    handle_rank,
    handle_identify,
    handle_deploy,
    handle_cleanup,
)


@dataclass
class Credentials:
    domain: str
    username: str
    password: str


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
    credentials = None
    if "credentials" in args:
        domain, username, password = parse_credentials(args.credentials)
        credentials = Credentials(domain=domain, username=username, password=password)
    else:
        credentials = Credentials(domain="", username="", password="")

    # Setup Logging
    log_queue = Manager().Queue(-1)
    listener = configure_queue_listener(
        logfile="linksiren.log",
        queue=log_queue,
        credentials=credentials,
        mode=args.mode,
    )

    try:
        logger = configure_main_logger(
            logfile="linksiren.log", credentials=credentials, mode=args.mode
        )
        logger.info("Starting linksiren")

        if args.mode == "generate":
            handle_generate(args)
        elif args.mode == "rank":
            handle_rank(args, credentials, log_queue)
        elif args.mode == "identify":
            handle_identify(args, credentials, log_queue)
        elif args.mode == "deploy":
            handle_deploy(args, credentials)
        elif args.mode == "cleanup":
            handle_cleanup(args, credentials)
    finally:
        # Ensure cleanup
        logger.info("Terminating linksiren")
        log_queue.put(None)
        listener.join()


if __name__ == "__main__":
    main()
