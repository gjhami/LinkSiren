"""
Author: George Hamilton
This module defines the HostTarget class, which represents a target host and its shares. The class
provides methods to manage connections, interact with shares, and perform operations such as writing
and deleting payloads, as well as reviewing folders for active files.
Classes:
    HostTarget: Represents a target host and its shares, providing methods to manage connections and
    interact with shares.
Usage Example:
    target = HostTarget(host='192.168.1.1')
    target.connect(user='admin', password='password')
    target.expand_paths()
    target.write_payload(path='share\\folder', payload_name='payload.txt', payload=b'Hello, World!')
    target.delete_payload(path='share\\folder', payload_name='payload.txt')
    folder_rankings = target.review_all_folders(folder_rankings={}, \
                            active_threshold_date=1625097600, \
                            depth=2, fast=True)
"""

import logging
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_MASK
import linksiren.pure_functions


class HostTarget:
    """
    Class to represent a target host and its shares

    Attributes:
    host: str - the hostname or IP address of the target
    """

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

    # Pure functions
    def add_path(self, path: str):
        """
        Adds a new path to the list of paths if it is not already present.

        Args:
            path (str): The path to be added to the list of paths.
        """
        if path not in self.paths:
            self.paths.append(path)

    # Impure functions
    def connect(self, credentials, lmhash="", nthash="", ntlmFallback=True):
        """
        Establishes a connection to the SMB server and logs in with the provided credentials.

        Parameters:
            user (str): The username for authentication. Default is an empty string.
            password (str): The password for authentication. Default is an empty string.
            domain (str): The domain for authentication. Default is an empty string.
            lmhash (str): The LM hash for authentication. Default is an empty string.
            nthash (str): The NT hash for authentication. Default is an empty string.
            ntlmFallback (bool): Whether to fallback to NTLM authentication. Default is True.

        Returns:
            None

        Raises:
            SessionError: If there is an error connecting to or logging into the SMB server.
        """
        logger = logging.getLogger("main_logger")

        if self.connection is None:
            try:
                self.connection = SMBConnection(remoteName=self.host, remoteHost=self.host)
            except SessionError as e:
                logger.error(
                    "Failed to connect to host.",
                    extra={"path": f"\\\\{self.host}", "exception": str(e)},
                )
                self.connection = None
                return

            try:
                self.connection.login(
                    credentials.username,
                    credentials.password,
                    credentials.domain,
                    lmhash,
                    nthash,
                    ntlmFallback,
                )
                self.logged_in = True
            except SessionError as e:
                self.connection = None
                logger.error(
                    "Failed to connect to host.",
                    extra={"path": f"\\\\{self.host}", "exception": str(e)},
                )

    def expand_paths(self):
        """
        Expands the paths by populating shares if an empty string is found in the paths list.

        This method checks if there is an empty string in the `paths` attribute. If found, it calls
        the `populate_shares` method to populate the shares and then removes the empty string from
        the `paths` list.
        """
        if "" in self.paths:
            self.populate_shares()
            self.paths.remove("")

    def populate_shares(self):
        """
        Populates the list of shares available on the connected host.
        This method checks if a connection to the host has been established.
        If not, it prints an error message and returns. If a connection is
        present, it attempts to retrieve the list of shares from the host.
        If the retrieval fails, it prints an error message and returns.
        The method then iterates over the retrieved shares, filtering out
        those that do not support tree connections (e.g., IPC$ shares).
        For each valid share, it adds the share name to the list of paths.

        Raises:
            SessionError: If there is an issue retrieving the list of shares
                  from the host.

        Returns:
            None
        """
        logger = logging.getLogger("main_logger")

        # Make sure a connection has been made to the host
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

        shares = []
        for share_info in resp:
            share_name = share_info["shi1_netname"][:-1]
            share_type = share_info["shi1_type"]

            # Check that the share type supports treeconnect, i.e. not IPC$, etc.
            if share_type & STYPE_MASK == STYPE_DISKTREE:
                shares.append(share_name)

        for share in shares:
            self.add_path(share)

    def write_payload(self, path: str, payload_name: str, payload: bytes):
        """
        Writes a payload to a specified path on a remote share.

        Args:
            path (str): The path to the directory on the remote share where the payload
                        will be written.
            payload_name (str): The name of the payload file to be created.
            payload (bytes): The binary data to be written to the payload file.

        Returns:
            bool: True if the payload was successfully written, False otherwise.

        Raises:
            Exception: If any error occurs during the connection, file creation, writing, or
                       closing processes.

        Notes:
            - The method assumes that `self.connection` is an established connection to the
                remote host.
            - The method handles exceptions internally and prints error messages for debugging
                purposes.
        """
        share = path.split("\\")[0]
        folder = "\\".join(path.split("\\")[1:])
        if folder == "":  # If the folder is the root of the share
            payload_path = payload_name
        else:
            payload_path = f"{folder}\\{payload_name}"

        full_path = f"\\\\{self.host}\\{share}\\{payload_path}"
        logger = logging.getLogger("main_logger")

        # Make sure a connection has been made to the host
        if self.connection is None:
            logger.error(
                "Failed to write payload. Not connected to host",
                extra={"path": f"\\\\{self.host}"},
            )
            return None

        # Try to create a Tree connection to the share
        try:
            tree_id = self.connection.connectTree(share=share)
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not connected to share.",
                extra={"path": f"\\\\{self.host}\\{share}", "exception": str(e)},
            )
            return None

        # Try to open a file for writing
        try:
            file_handle = self.connection.createFile(tree_id, payload_path)
            logger.info(" for writing.", extra={"path": full_path})
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not create file.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        # Try to write to the file
        try:
            self.connection.writeFile(treeId=tree_id, fileId=file_handle, data=payload)
            logger.info("Successfuly wrote payload file.", extra={"path": full_path})
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not write to open file.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        # Try to close the file
        try:
            self.connection.closeFile(treeId=tree_id, fileId=file_handle)
        except Exception as e:
            logger.error(
                "Failed to write payload. Could not close file after writing.",
                extra={"path": full_path, "exception": str(e)},
            )
            return None

        # Try to close the Tree connection to the share
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
        """
        Delete all payloads from target paths.
        Attempts to delete payload files from each path stored in self.paths.
        For each failed deletion, the full network path is added to a list.

        Returns:
            list: A list of network paths where payload deletion failed.
                  Empty list if all deletions were successful.
                  Paths are in the format '\\host\path'.
        """

        payloads_not_deleted = []
        for path in self.paths:
            result = self.delete_payload(path)
            if result is False:
                payloads_not_deleted.append(f"\\\\{self.host}\\{path}")
        return payloads_not_deleted

    def delete_payload(self, path: str):
        """
        Deletes a specified payload from a given path on a remote share.

        Args:
            path (str): The path to the directory on the remote share.
            payload_name (str): The name of the payload to be deleted.

        Returns:
            bool: True if the payload was successfully deleted, False otherwise.

        Raises:
            Exception: If an error occurs during the deletion process.

        Notes:
            - The method assumes that the connection to the remote share is already established.
            - If the connection is not established, the method will print an error message and
                return False.
        """
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

    def review_all_folders(
        self, folder_rankings, active_threshold_date, depth, fast, ignore_folders=None
    ):
        """
        Reviews all folders and updates the folder rankings.

        This method iterates through all the folders in the `self.paths` list,
        reviews each folder, and updates the `folder_rankings` dictionary with
        the results.

        Parameters:
        folder_rankings (dict): A dictionary containing the initial rankings of folders.
        active_threshold_date (datetime): The threshold date to determine active folders.
        depth (int): The depth to which the folders should be reviewed.
        fast (bool): A flag indicating whether to perform a fast review.

        Returns:
        dict: Updated folder rankings after reviewing all folders.
        """
        logger = logging.getLogger("main_logger")

        if self.connection is None:
            logger.error(
                "Failed to review folders. Not connected to host.",
                extra={"path": f"\\\\{self.host}"},
            )
            return
        else:
            for folder in self.paths:
                unc_path = f"\\\\{self.host}\\{folder}"
                logger.debug("Started reviewing path", extra={"path": unc_path})
                if folder not in ignore_folders:
                    folder_rankings = {
                        **folder_rankings,
                        **self.review_folder(
                            folder_rankings, folder, active_threshold_date, depth, fast
                        ),
                    }
                else:
                    logger.debug(
                        "Skipping review of share or folder based on the --ignore-shares argument.",
                        extra={"path": unc_path},
                    )
            return folder_rankings

    def review_folder(self, folder_rankings, path, active_threshold_date, depth, fast):
        """
        review_folder(folder_rankings, path, active_threshold, depth, fast)

        :param dict folder_rankings: Dictionary of folder UNC paths and rankings reflecting the
        number of active files in the folder. {<folder UNC path>: <ranking>}
        :param str path: Path to the folder being accessed, excluding the host name. For example,
        if the folder is located at \\\\host\\share\\folder, then the path is 'share\\folder'.
        :param int active_threshold: Number of days within which file access constitutes a file
        being active
        :param int depth: Number of layers of folders to search. 1 searches only the specified
        folder and none of its subfolders.
        :param bool fast: If True, the current folder will be marked as active as soon as a
        single file is found. A rank of 1 will be assigned to all active folders.

        :return: Dictionary of folder UNC paths as keys and rankings as values

        Iterates over files and subfolders starting at the specified UNC path up to the
        specified depth. Each folder is assigned a rank, tracked in folder rankings by its
        UNC path, based on the number of active files it contains. Active files are files
        accessed within the number of days specified in active threshold. If fast is set
        to True, then the folder will receive a rank of 1 or 0 depending on if it contains
        at least one active file or none.
        """
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
            reviewed = fast and ranking > 0  # Review completed if in fast and ranking is non-zero
            is_file = not listing.is_directory()
            name = listing.get_longname()

            # If folder is active and max_depth is reached
            if reviewed and depth_reached:
                break  # Stop reviewing items in the folder

            # For active files in the directory when the review is not yet completed
            elif (
                not reviewed
                and is_file
                and linksiren.pure_functions.is_active_file(
                    access_time=listing.get_atime_epoch(),
                    threshold_date=active_threshold_date,
                )
            ):
                ranking += 1  # Increment the folder ranking

            # For subfolders in the directory
            elif not (is_file or depth_reached or name == "." or name == ".."):
                # If max depth is not reached
                if folder == "":
                    subfolder_path = f"{share}\\{name}"
                else:
                    subfolder_path = f"{share}\\{folder}\\{name}"
                subfolders.append(f"{subfolder_path}")  # Add the subfolder to the list of folders

        # Recursion: Call this function on all subfolders to review them if\
        # max depth is not reached.
        # Update folder_rankings as each subfolder is reviewed.
        if not depth_reached:  # If the max depth has not been reached
            for subfolder in subfolders:
                # Requires python 3.9 or greater
                folder_rankings = folder_rankings | self.review_folder(
                    folder_rankings, subfolder, active_threshold_date, depth - 1, fast
                )

        # Update folder_rankings with the rank of the current folder and return it
        folder_rankings[f"\\\\{self.host}\\{path}"] = ranking
        return folder_rankings
