import re
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Typical SSH auth log regex patterns
FAILED_REGEX = re.compile(r"Failed \w+ for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
SUCCESS_REGEX = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
SUDO_REGEX = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.*)")
TIMESTAMP_REGEX = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})")

def parse_log(log_entry):
    """
    Parse raw log entry into structured dictionary format.
    Extracts IP address, username, event type, and timestamp.
    """
    from detection import analyze_event
    
    parsed_data = None
    
    # Attempt to extract syslog timestamp, fallback to current time
    timestamp_match = TIMESTAMP_REGEX.search(log_entry)
    timestamp = timestamp_match.group("timestamp") if timestamp_match else datetime.now().isoformat()
    
    # Check for failed login
    failed_match = FAILED_REGEX.search(log_entry)
    if failed_match:
        parsed_data = {
            "event": "failed_login",
            "ip": failed_match.group("ip"),
            "user": failed_match.group("user"),
            "timestamp": timestamp,
            "raw_log": log_entry
        }
    else:
        # Check for successful login
        success_match = SUCCESS_REGEX.search(log_entry)
        if success_match:
            parsed_data = {
                "event": "successful_login",
                "ip": success_match.group("ip"),
                "user": success_match.group("user"),
                "timestamp": timestamp,
                "raw_log": log_entry
            }
        else:
            # Check for sudo usage
            sudo_match = SUDO_REGEX.search(log_entry)
            if sudo_match:
                parsed_data = {
                    "event": "sudo_usage",
                    "ip": "localhost",
                    "user": sudo_match.group("user"),
                    "command": sudo_match.group("command"),
                    "timestamp": timestamp,
                    "raw_log": log_entry
                }
            
    if parsed_data:
        # Forward the parsed object to the detection engine
        analyze_event(parsed_data)
        
    return parsed_data

