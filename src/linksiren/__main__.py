import json
from datetime import datetime
from pathlib import Path
from impacket.examples.utils import parse_credentials
from linksiren.arg_parser import parse_args
from linksiren.mode_handlers import handle_generate, handle_rank, handle_identify, handle_deploy, handle_cleanup

def main():
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