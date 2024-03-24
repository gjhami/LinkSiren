from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_MASK
import linksiren.pure_functions

class HostTarget:
    '''
    Class to represent a target host and its shares

    Attributes:
    host: str - the hostname or IP address of the target
    '''
    def __init__(self, host: str, paths: list[str] = [], connection: SMBConnection = None, logged_in: bool = False):
        self.host = host
        self.paths = paths
        self.connection = connection
        self.logged_in = logged_in

        if self.connection is not None and self.host is None:
            self.host = self.connection.getRemoteHost()

    # Pure functions
    def add_path(self, path: str):
        if path not in self.paths:
            self.paths.append(path)

    # Impure functions
    def connect(self, user='', password='', domain = '', lmhash = '', nthash = '', ntlmFallback = True):
        if self.connection is None:
            try:
                self.connection = SMBConnection(remoteName=self.host, remoteHost=self.host)
            except SessionError as e:
                print(f'Error connecting to {self.host}: {e}')

            try:
                self.connection.login(user, password, domain, lmhash, nthash, ntlmFallback)
                self.logged_in = True
            except SessionError as e:
                self.connection = None
                print(f'Error logging into {self.host}: {e}')

    def expand_paths(self):
        if '' in self.paths:
            self.populate_shares()
            self.paths.remove('')

    def populate_shares(self):
        # Make sure a connection has been made to the host
        if self.connection is None:
            print(f'Error: Not connected to {self.host}')
            return
        else:
            try:
                resp = self.connection.listShares()
            except Exception as e:
                print(f'Failed to connect to get shares for host: {self.host}\n\t{e}')

        shares = []
        for share_info in range(len(resp)):
            share_name = resp[share_info]['shi1_netname'][:-1]
            share_type = resp[share_info]['shi1_type']

            # Check that the share type supports treeconnect, i.e. not IPC$, etc.
            if share_type & STYPE_MASK == STYPE_DISKTREE:
                shares.append(share_name)

        for share in shares:
            self.add_path(share)

    def write_payload(self, path: str, payload_name: str, payload: bytes):
        share = path.split('\\')[0]
        folder = '\\'.join(path.split('\\')[1:])
        payload_path = f'{folder}\\{payload_name}'

        # Make sure a connection has been made to the host
        if self.connection is None:
            print(f'Error: Not connected to {self.host}')
            return
        else:
            # Try to create a Tree connection to the share
            try:
                tree_id = self.connection.connectTree(share=share)
            except Exception as e:
                print("Failed to connect to share: " + str(e))
                return False

            # Try to open a file for writing
            try:
                file_handle = self.connection.createFile(tree_id, payload_path)
            except Exception as e:
                print("Failed to create payload file: " + str(e))
                print(f'\tPath: {path}\tPayload: {payload_name}')
                return False

            # Try to write to the file
            try:
                bytes_written = self.connection.writeFile(treeId=tree_id, fileId=file_handle, data=payload)
            except Exception as e:
                print("Failed to write to payload file: " + str(e))
                return False

            # Try to close the file
            try:
                self.connection.closeFile(treeId=tree_id, fileId=file_handle)
            except Exception as e:
                print("Failed to close file: " + str(e))
                return False

            # Try to close the Tree connection to the share
            try:
                self.connection.disconnectTree(tree_id)
            except Exception as e:
                print("Failed to disconnect tree: " + str(e))
                return False

            return True

    def delete_payload(self, path: str, payload_name: str):
        share = path.split('\\')[0]
        folder = '\\'.join(path.split('\\')[1:])
        payload_path = f'{folder}\\{payload_name}'

        if self.connection is None:
            print(f'Error: Not connected to {self.host}')
            return
        else:
            try:
                self.connection.deleteFile(shareName=share, pathName=payload_path)
            except Exception as e:
                print("Failed to delete payload: " + str(e))

    def review_all_folders(self, folder_rankings, active_threshold_date, depth, fast):
        if self.connection is None:
            print(f'Error: Not connected to {self.host}')
            return
        else:
            for folder in self.paths:
                folder_rankings = {**folder_rankings, **self.review_folder(folder_rankings, folder, active_threshold_date, depth, fast)}
            return folder_rankings

    def review_folder(self, folder_rankings, path, active_threshold_date, depth, fast):
        """
        review_folder(folder_rankings, path, active_threshold, depth, fast)

        :param dict folder_rankings: Dictionary of folder UNC paths and rankings reflecting the number
        of active files in the folder. {<folder UNC path>: <ranking>}
        :param str path: UNC path for the current folder being reviewed
        :param int active_threshold: Number of days within which file access constitutes a file being
        active
        :param int depth: Number of layers of folders to search. 1 searches only the specified folder
        and none of its subfolders.
        :param bool fast: If True, the current folder will be marked as active as soon as a single file
        is found. A rank of 1 will be assigned to all active folders.

        :return: Dictionary of folder UNC paths as keys and rankings as values

        Iterates over files and subfolders starting at the specified UNC path up to the
        specified depth. Each folder is assigned a rank, tracked in folder rankings by its
        UNC path, based on the number of active files it contains. Active files are files
        accessed within the number of days specified in active threshold. If fast is set
        to True, then the folder will receive a rank of 1 or 0 depending on if it contains
        at least one active file or none.
        """
        ranking = 0
        subfolders = []
        reviewed = False
        depth_reached = depth <= 1

        share = path.split('\\')[0]
        folder = '\\'.join(path.split('\\')[1:])

        try:
            listings = self.connection.listPath(shareName=share, path=f'{folder}\\*')
        except Exception as e:
            unc_path = f'\\\\{self.host}\\{share}'
            if folder != '':
                unc_path = unc_path + f'\\{folder}'
            unc_path = unc_path + '\\*'
            print(f'Failed to review path: {unc_path}\n\t{e}')
            return folder_rankings

        for listing in listings:
            reviewed = fast and ranking > 0 # Review completed if in fast and ranking is non-zero
            is_file = not listing.is_directory()
            name = listing.get_longname()

            # If folder is active and max_depth is reached
            if reviewed and depth_reached:
                break  # Stop reviewing items in the folder

            # For active files in the directory when the review is not yet completed
            elif not reviewed and is_file and linksiren.pure_functions.is_active_file(access_time=listing.get_atime_epoch(), threshold_date=active_threshold_date):
                ranking += 1 # Increment the folder ranking

            # For subfolders in the directory
            elif not (is_file or depth_reached or name == '.' or name == '..'): # If max depth is not reached
                if folder == '':
                    subfolder_path = f'{share}\\{name}'
                else:
                    subfolder_path = f'{share}\\{folder}\\{name}'
                subfolders.append(f'{subfolder_path}') # Add the subfolder to the list of folders

        # Recursion: Call this function on all subfolders to review them if max depth is not reached.
        # Update folder_rankings as each subfolder is reviewed.
        if not depth_reached:  # If the max depth has not been reached
            for subfolder in subfolders:
                folder_rankings = {**folder_rankings, **self.review_folder(folder_rankings, subfolder,
                                                                active_threshold_date, depth - 1, fast)}
                # Requires python 3.9 or greater, commented for >= python 3.5 compatability
                # folder_rankings = folder_rankings | self.review_folder(folder_rankings, subfolder,
                #                                                  active_threshold_date, depth - 1, fast)

        # Update folder_rankings with the rank of the current folder and return it
        folder_rankings[f'\\\\{self.host}\\{path}'] = ranking
        return folder_rankings
