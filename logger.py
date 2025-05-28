import logging

def get_logger(name="asa2yaml", log_file="asa2yaml.log"):
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        fh = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger