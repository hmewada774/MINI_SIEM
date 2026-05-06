import time
import os
import logging

logger = logging.getLogger(__name__)

def tail(file_path):
    """Generator that yields new lines from a file in real-time (like tail -f)."""
    while True:
        try:
            if not os.path.exists(file_path):
                # Optionally create the file if it doesn't exist
                try:
                    open(file_path, 'a').close()
                except:
                    pass
                    
            with open(file_path, 'r') as f:
                # Move the pointer to the end of the file to start reading new lines
                f.seek(0, os.SEEK_END)
                logger.info(f"Successfully monitoring {file_path}")
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)  # Sleep briefly to avoid high CPU usage
                        continue
                    yield line
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}. Retrying in 5 seconds...")
            time.sleep(5)
        except PermissionError:
            logger.error(f"Permission denied: {file_path}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected error reading {file_path}: {e}")
            time.sleep(5)

def start_collector():
    """Start listening for incoming logs."""
    # Importing here ensures we use the correct module from sys.path and avoids circular dependencies
    from parser import parse_log
    
    log_file = "/var/log/auth.log"
    logger.info(f"Starting real-time log collector for: {log_file}")
    
    for line in tail(log_file):
        line = line.strip()
        if line:
            # Send each log line to the parser module
            parsed_data = parse_log(line)
            # In the future, parsed_data can be forwarded to detection/database here

