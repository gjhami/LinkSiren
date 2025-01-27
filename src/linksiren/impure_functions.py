"""
Author: George Hamilton
Description: This module is used to rank and filter the optimal share locations for deploying
payloads that coerce authentication based on recent access. This module can then be used to bulk
deploy multiple types of payloads to the identified locations. Lastly, this module can be used to
bulk cleanup multiple types of payloads from the identified locations.
"""

import logging
import logging.handlers
from pathlib import Path
from multiprocessing import Pool
from functools import partial
from tqdm import tqdm
import linksiren.pure_functions
from linksiren.logging_config import configure_worker_logging


def worker_configurer(log_queue):
    """Configure logging in worker process"""
    configure_worker_logging(log_queue)


def worker_wrapper(target, worker_partial, log_queue):
    worker_configurer(log_queue)
    logger = logging.getLogger("main_logger")
    try:
        return worker_partial(target)
    except Exception as e:
        logger.error(
            "Error processing target",
            extra={"path": f"\\\\{target.host}", "exception": str(e)},
        )
        return None


def write_payload_local(payload_name, payload_contents):
    """
    write_payload_local(payload_name, payload_contents)

    :param str payload_name: File name, including extension, of the payload
    :param str payload_contents: Contents to write to the payload file


    :return: A bool indicateing whether or not the payload was written successfully.

    Accepts a folder path, payload name, and payload contents. Writes the supplied contents
    to the specified file and folder. Returns a bool indicating if the payload was written
    successfully.
    """
    extension = Path(payload_name).suffix
    logger = logging.getLogger("main_logger")

    if extension == ".lnk":
        try:  # Try to write the payload
            with open(payload_name, mode="wb") as payload_file:
                payload_file.write(payload_contents)
        except Exception as e:
            # Print a message and don't track the folder if writing the payload to it fails
            logger.error(
                "Failed to write payload locally.",
                extra={"path": payload_name, "exception": str(e)},
            )
            return False
    else:
        try:  # Try to write the payload
            with open(payload_name, mode="w", newline="\r\n", encoding="utf-8") as payload_file:
                payload_file.write(payload_contents)
        except Exception as e:
            # Print a message and don't track the folder if writing the payload to it fails
            logger.error(
                "Failed to write payload locally.",
                extra={"path": payload_name, "exception": str(e)},
            )
            return False

    logger.info("Successfully wrote payload locally.", extra={"path": payload_name})

    # If writing the payload doesn't fail, then return True
    return True


def read_targets(targets_file):
    """
    read_targets(targets_file)

    :param str targets_file: Path to a text file containing UNC paths to file shares and base
    directories.
    :return: List of target UNC paths

    Reads in a list of targets from a specified file path and returns a list of targets.
    Catches an exception and prints an error if the targets file does not exist.
    """
    target_unc_paths = []
    logger = logging.getLogger("main_logger")

    # Read share targets into an array
    try:
        with open(targets_file, "r", encoding="utf-8") as file:
            target_unc_paths = file.read().splitlines()
    except Exception as e:
        logger.error(
            "Failed to read targets file. Make sure it exists and review its permissions.",
            extra={"path": targets_file, "exception": str(e)},
        )
    return linksiren.pure_functions.process_targets(target_unc_paths)


def get_rankings_for_target(
    target, credentials, active_threshold_date, max_depth, go_fast, ignore_folders
):
    folder_rankings = {}
    logger = logging.getLogger("main_logger")

    if target.connection is None:
        try:
            target.connect(credentials=credentials)
        except Exception as e:
            logger.error(
                "Could not connect to host",
                extra={"path": target.host, "exception": str(e)},
            )
            return folder_rankings

    # Expand any empty paths for the target
    # An empty path indicates all shares on the host should be targeted
    try:
        target.expand_paths()
    except Exception as e:
        logger.error(
            "Failed to expand paths for specified host.",
            extra={"path": target.host, "exception": str(e)},
        )
        return folder_rankings

    try:
        # Call the appropriate review function based on the fast argument
        logger.info("Reviewing folders on host", extra={"path": f"\\\\{target.host}"})
        folder_rankings = target.review_all_folders(
            folder_rankings, active_threshold_date, max_depth, go_fast, ignore_folders
        )
        logger.info("Finished reviewing folders on host", extra={"path": f"\\\\{target.host}"})
    except Exception as e:
        logger.error(
            "Finished reviewing folders on host",
            extra={"path": f"\\\\{target.host}", "exception": str(e)},
        )

    return folder_rankings


# Eventually we should just pass the whole parsed arguments structure to different functions
# And then modify behaviors by checking options for things like active_threshold_date, max_depth
# creds/ntlm hash, go_fast, etc.
def get_rankings(
    targets,
    credentials,
    active_threshold_date,
    max_depth,
    go_fast,
    log_queue,
    max_concurrency,
    ignore_folders,
):
    """
    get_rankings(targets, domain, username, password, active_threshold_date, max_depth, go_fast)

    :param str domain: Domain for authentication.
    :param str username: Username for authentication.
    :param str password: Password for authentication.
    :param datetime active_threshold_date: Date threshold to determine if a file is active.
    dictionary of UNC paths and associated rankings. Catches exceptions for failed smb connections
    :param int max_depth: Number of layers of folders to search. 1 searches only the specified
    target UNC paths and none of their subfolders.
    :param bool go_fast: If True, folders will be marked as active as soon as a single file is
    meeting the active_threshold criteria is found. A rank of 1 will be assigned to all active
    folders.

    :return: A dictionary in the format {<folder UNC path>: <ranking>}

    Accepts a list of UNC target objects. Gets rankings associated with each path associated with
    each target based on the number of files active within the active_threshold number of days.
    Recursively assigns ranking to subfolders up to max_depth. If go_fast is enabled, assigns the
    rank of 1 to all folders with a single active file and moves on to the next folder. Returns a
    dirctionary of UNC paths and associated rankings. Catches exceptions for failed smb connections
    and prints a message describing the error.
    """
    # Track rankings for each folder, which are (counterintuitively) scores corresponding to the
    # number of active files in a folder. So a higher ranking is a better target.
    # {<folder UNC path>: <ranking>}
    folder_rankings = {}
    logger = logging.getLogger("main_logger")

    worker_partial = partial(
        get_rankings_for_target,
        credentials=credentials,
        active_threshold_date=active_threshold_date,
        max_depth=max_depth,
        go_fast=go_fast,
        ignore_folders=ignore_folders,
    )

    num_workers = max_concurrency
    if len(targets) < num_workers:
        num_workers = len(targets)

    logger.debug("Using %d worker processes to crawl %d target hosts", num_workers, len(targets))

    with Pool(processes=num_workers) as pool:
        for result in tqdm(
            pool.imap_unordered(
                func=partial(worker_wrapper, worker_partial=worker_partial, log_queue=log_queue),
                iterable=targets,
            ),
            total=len(targets),
        ):
            if result is not None:  # Result is None if an error occurred
                folder_rankings.update(result)  # Update the folder rankings with the results

        pool.close()  # Close the pool to prevent further tasks from being submitted
        pool.join()  # Wait for all worker processes to finish

    return folder_rankings


def get_sorted_rankings(
    targets,
    credentials,
    active_threshold_date,
    max_depth,
    go_fast,
    log_queue,
    max_concurrency,
    ignore_folders,
):
    """
    Retrieve and sort rankings for given targets.
    This function fetches the rankings for the specified folders and sorts them
    based on their rankings.
    Args:
        targets (list): List of target folders to rank.
        domain (str): Domain to authenticate against.
        username (str): Username for authentication.
        password (str): Password for authentication.
        active_threshold_date (str): Date threshold to consider for active rankings.
        max_depth (int): Maximum depth to search within folders.
        go_fast (bool): Flag to enable faster processing.
    Returns:
        list: Sorted rankings of the folder UNC paths.
    """
    # Get rankings for folders
    folder_rankings = get_rankings(
        targets,
        credentials,
        active_threshold_date,
        max_depth,
        go_fast,
        log_queue,
        max_concurrency,
        ignore_folders=ignore_folders,
    )

    # Sort the folder UNC paths by rankings
    sorted_rankings = linksiren.pure_functions.sort_rankings(folder_rankings)
    return sorted_rankings


def write_list_to_file(input_list, file_path, mode="w"):
    """
    write_list_to_file(list, file_path)

    :param list list: A list
    :param str file_path: Path to a file to which to write
    :param str mode: String indicating the mode in which to open the output file.
    Defaults to 'w' for write.

    Writes items in a list to a specified file, one per line.
    """
    with open(file_path, mode=mode, encoding="utf-8") as f:
        for item in input_list:
            f.write(item + "\n")


def get_lnk_template(template_path):
    """
    Reads a binary file from the given template path and returns its content as a list of bytes.
    Args:
        template_path (str): The path to the binary file to be read.
    Returns:
        list: A list of bytes representing the content of the binary file.
    """
    with open(template_path, "rb") as lnk:
        shortcut = list(lnk.read())

    return shortcut
