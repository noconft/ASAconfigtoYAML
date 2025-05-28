import logging
import os
from logging.handlers import RotatingFileHandler

def get_logger(name="asa2yaml", log_file="asa2yaml.log", max_bytes=2*1024*1024, backup_count=3):
    """
    Creates and configures a logger.

    Parameters:
    - name (str): Name of the logger.
    - log_file (str): Name of the log file.
    - max_bytes (int): Maximum size of a log file in bytes before rotating. Default is 2MB.
    - backup_count (int): Number of backup log files to keep. Default is 3.
    """
    log_dir = os.path.join(os.path.dirname(__file__), "log")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, log_file)

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        # Use RotatingFileHandler: 3 files of 2MB each before rotating
        fh = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger