"""
Author: George Hamilton
HostTarget. One SMB target with helpers to enumerate shares, write/delete
payloads, and recursively rank folders.
"""

import logging
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_MASK
import linksiren.pure_functions


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

        * ``credentials.anonymous`` -> ``SMBConnection.login`` with empty
          user / password / domain (NULL session). Most modern hosts deny
          this, but it is the right probe for "test for anonymous access
          to shares" recon.
        * ``credentials.use_kerberos`` -> ``SMBConnection.kerberosLogin``
          (a ccache referenced by ``$KRB5CCNAME`` is honored automatically
          by Impacket when no TGT/TGS is supplied). When the target host
          is an IP literal, an attempt is made to reverse-DNS it to an
          FQDN so the cifs/<host> SPN can be located.
        * otherwise -> ``SMBConnection.login`` with password and/or NTLM hash.
        """
        logger = logging.getLogger("main_logger")

        if self.connection is not None:
            # Already connected. Login was either done elsewhere or via the
            # connection that was passed in at construction.
            return

        # Kerberos SPN lookup needs an FQDN, not an IP. If Kerberos is in
        # use and self.host is an IP, try reverse DNS so cifs/<host> can
        # resolve. Keep the original IP as the network endpoint
        # (remoteHost) but expose the FQDN as remoteName so the SPN is
        # constructed right.
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
                            "cifs SPN. If KDC rejects, list the host by "
                            "exact-FQDN in the targets file.",
                            self.host, remote_name,
                            extra={"path": f"\\\\{self.host}"},
                        )
                except (socket.herror, socket.gaierror) as e:
                    logger.warning(
                        "-k against IP target and reverse DNS failed (%s); "
                        "Kerberos may reject with KDC_ERR_S_PRINCIPAL_UNKNOWN. "
                        "Use FQDN UNC paths in your targets file.", e,
                        extra={"path": f"\\\\{self.host}"},
                    )
            except ValueError:
                pass  # self.host is already a hostname

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
                # NULL session: empty user, empty password, empty domain.
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
    def write_payload(self, path: str, payload_name: str, payload: bytes):
        """Write ``payload`` to ``\\\\host\\path\\payload_name``.

        Returns the full UNC path on success, or ``None`` on any failure
        before the bytes were committed. A failure to close the file or
        disconnect the tree after the write is logged but still treated as
        success and returns the UNC path. The bytes are on disk.
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

        try:
            file_handle = self.connection.createFile(tree_id, payload_path)
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
            return full_path

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
