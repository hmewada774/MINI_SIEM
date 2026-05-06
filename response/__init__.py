import logging
import subprocess
from datetime import datetime
from database import insert_alert, insert_blocked_ip, is_ip_blocked
from config import Config

logger = logging.getLogger(__name__)

# ANSI colors for terminal output
COLORS = {
    "LOW": "\033[94m",     # Blue
    "MEDIUM": "\033[93m",  # Yellow
    "HIGH": "\033[91m",    # Red
    "RESET": "\033[0m"
}

def generate_alert(alert_type, ip, severity, description="", user=None, timestamp=None):
    """
    Reusable alert generation function.
    Stores the alert in MongoDB and prints a colored alert to the terminal.
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()
        
    severity = severity.upper()
    
    alert_data = {
        "type": alert_type,
        "ip": ip,
        "severity": severity,
        "description": description,
        "user": user,
        "timestamp": timestamp
    }
    
    # Store in MongoDB
    insert_alert(alert_data)
    
    # Print alert in terminal
    color = COLORS.get(severity, COLORS["RESET"])
    reset = COLORS["RESET"]
    print(f"\n{color}[!] NEW SIEM ALERT: [{severity}] {alert_type}{reset}")
    print(f"{color}    IP Address : {ip}{reset}")
    if user:
        print(f"{color}    User       : {user}{reset}")
    print(f"{color}    Details    : {description}{reset}")
    print(f"{color}    Time       : {timestamp}{reset}\n")
    
    # Trigger automated response for HIGH severity alerts
    if severity == "HIGH":
        block_ip(ip, reason=alert_type)
        
    return alert_data

def block_ip(ip, reason=""):
    """Block an IP address using iptables if active response is enabled."""
    if not Config.ENABLE_ACTIVE_RESPONSE:
        logger.info(f"Active response disabled in config. Not blocking IP: {ip}")
        return False
        
    if not ip or ip in ["localhost", "127.0.0.1", "::1"]:
        logger.warning(f"Attempted to block safe/invalid IP: {ip}")
        return False
        
    if is_ip_blocked(ip):
        logger.info(f"IP {ip} is already blocked.")
        return False
        
    try:
        # Safely run iptables command using subprocess
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Store blocked IP in database
        insert_blocked_ip(ip, reason)
        
        color = COLORS["HIGH"]
        reset = COLORS["RESET"]
        print(f"\n{color}[!] ACTIVE RESPONSE: Blocked IP {ip} (Reason: {reason}){reset}\n")
        logger.info(f"Successfully blocked IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP {ip} using iptables. Error: {e.stderr}")
    except FileNotFoundError:
        logger.error("iptables command not found. Ensure you are running on Linux as root.")
    except Exception as e:
        logger.error(f"Unexpected error blocking IP {ip}: {e}")
        
    return False

def trigger_response(alert_data):
    """Legacy entry point, wraps generate_alert."""
    return generate_alert(
        alert_type=alert_data.get("rule", alert_data.get("type", "Unknown Event")),
        ip=alert_data.get("ip", "Unknown"),
        severity=alert_data.get("severity", "MEDIUM"),
        description=alert_data.get("description", ""),
        user=alert_data.get("user"),
        timestamp=alert_data.get("timestamp")
    )

