from multiprocessing import Process
import logging
import logging.handlers
import json
import sys
import traceback
import time


class JSONFormatter(logging.Formatter):
    def __init__(self, credentials=None, mode=None):
        self.credentials = credentials
        self.mode = mode
        super().__init__()

    def format(self, record):
        log_record = {
            "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "Level": record.levelname,
            "Message": record.getMessage(),
            "Path": getattr(record, "path", None),
            "User": getattr(
                record,
                "credentials",
                f"{self.credentials.username}@{self.credentials.domain}",
            ),
            "Mode": getattr(record, "mode", self.mode),
            "Exception": getattr(record, "exception", None),
        }
        return json.dumps(log_record)


def configure_main_logger(credentials, mode, logfile="linksiren.log"):
    """
    Creates a logger named 'main_logger' with a file handler.
    """
    logger = logging.getLogger("main_logger")
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(logfile)
    file_handler.setFormatter(JSONFormatter(credentials, mode))

    if not logger.handlers:
        logger.addHandler(file_handler)

    return logger


def listener_process(logfile, queue, credentials, mode):
    """Separate process to handle logging queue"""
    logger = logging.getLogger("main_logger")
    handler = logging.FileHandler(logfile)
    handler.setFormatter(JSONFormatter(credentials, mode))
    logger.addHandler(handler)

    while True:
        try:
            record = queue.get()
            if record is None:
                break
            logger.handle(record)
        except Exception:
            print("Logging error:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)


def configure_queue_listener(queue, credentials, mode, logfile="linksiren.log"):
    """Configure and start queue listener process"""
    listener = Process(target=listener_process, args=(logfile, queue, credentials, mode))
    listener.start()
    return listener


def configure_worker_logging(queue):
    """Configure worker process logging"""
    logger = logging.getLogger("main_logger")
    logger.addHandler(logging.handlers.QueueHandler(queue))
    logger.setLevel(logging.DEBUG)
