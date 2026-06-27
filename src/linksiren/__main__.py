"""
Author: George Hamilton
Main module for the LinkSiren application.

Parses command-line arguments, builds an :class:`AuthContext` from any supplied
credentials / hashes / Kerberos flags, and dispatches to the appropriate mode
handler.
"""

import os
import sys
from dataclasses import dataclass, field
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
class AuthContext:
    """All authentication parameters in one place.

    ``Credentials`` is preserved as an alias for backwards compatibility with
    callers that import the name.
    """

    domain: str = ""
    username: str = ""
    password: str = ""
    lmhash: str = ""
    nthash: str = ""
    aes_key: str = ""
    kdc_host: str | None = None
    use_kerberos: bool = False
    no_pass: bool = False


# Backwards-compatible alias. Older callers/tests import ``Credentials``.
Credentials = AuthContext


def _parse_hashes(hashes: str | None) -> tuple[str, str]:
    """Split a ``LMHASH:NTHASH`` argument into its two parts.

    A bare NT hash (no colon) is also accepted and returned as ``("", nthash)``.
    Empty / ``None`` input returns ``("", "")``.
    """
    if not hashes:
        return "", ""
    if ":" in hashes:
        lm, nt = hashes.split(":", 1)
        return lm, nt
    return "", hashes


def _build_auth_context(args) -> AuthContext:
    """Build an :class:`AuthContext` from parsed CLI arguments.

    ``generate`` mode has no credentials and yields an empty context.
    """
    if "credentials" not in args:
        return AuthContext()

    domain, username, password = parse_credentials(args.credentials)
    lmhash, nthash = _parse_hashes(getattr(args, "hashes", None))

    # ``-no-pass`` (or ``-k`` alone with a ccache) means we should not try the
    # supplied password. Clear it so Impacket doesn't accidentally use a bare
    # username string as a credential.
    if getattr(args, "no_pass", False) and not (lmhash or nthash):
        password = ""

    return AuthContext(
        domain=domain,
        username=username,
        password=password,
        lmhash=lmhash,
        nthash=nthash,
        aes_key=getattr(args, "aesKey", "") or "",
        kdc_host=getattr(args, "dc_ip", None),
        use_kerberos=getattr(args, "k", False),
        no_pass=getattr(args, "no_pass", False),
    )


def main():
    """Entry point. Parse args, set up logging, dispatch by mode."""
    args = parse_args()
    auth = _build_auth_context(args)

    # Kerberos requires KRB5CCNAME unless aesKey / hashes / password provided.
    if (
        auth.use_kerberos
        and not auth.aes_key
        and not auth.nthash
        and not auth.password
        and not os.environ.get("KRB5CCNAME")
    ):
        print(
            "error: -k was specified but no Kerberos credentials are available "
            "(no KRB5CCNAME, no password, no -hashes, no -aesKey).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Setup Logging
    log_queue = Manager().Queue(-1)
    listener = configure_queue_listener(
        logfile="linksiren.log",
        queue=log_queue,
        credentials=auth,
        mode=args.mode,
    )

    logger = configure_main_logger(logfile="linksiren.log", credentials=auth, mode=args.mode)
    try:
        logger.info("Starting linksiren")

        if args.mode == "generate":
            handle_generate(args)
        elif args.mode == "rank":
            handle_rank(args, auth, log_queue)
        elif args.mode == "identify":
            handle_identify(args, auth, log_queue)
        elif args.mode == "deploy":
            handle_deploy(args, auth)
        elif args.mode == "cleanup":
            handle_cleanup(args, auth)
    finally:
        logger.info("Terminating linksiren")
        log_queue.put(None)
        listener.join()


if __name__ == "__main__":
    main()
