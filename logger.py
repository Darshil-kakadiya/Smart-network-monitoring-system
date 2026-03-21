import logging
import os
import sys
from config import LOG_FILE

# Ensure logs directory exists
log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir)
    except Exception:
        pass

# Production Logging Configuration
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
except Exception:
    # Fallback if LOG_FILE is not writable
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

logger = logging.getLogger("BandwidthMgr")

def log_action(action, details):
    logger.info(f"{action}: {details}")

def log_error(error_msg):
    logger.error(error_msg)
