import time
import logging

logger = logging.getLogger(__name__)

# In-memory tracking cache
failed_logins = {}  # Format: { 'ip_address': [timestamp1, timestamp2, ...] }
known_ips = set()   # Format: { 'ip_address1', 'ip_address2' }

def analyze_event(event):
    """Analyze event against detection rules."""
    from response import generate_alert
    
    if not event:
        return None
        
    event_type = event.get('event')
    ip = event.get('ip')
    user = event.get('user')
    timestamp = event.get('timestamp')
    raw_log = event.get('raw_log', '')

    # 1. Brute Force Detection
    if event_type == 'failed_login':
        if _check_brute_force(ip):
            return generate_alert(
                alert_type="Brute Force Detection",
                severity="HIGH",
                description=f"More than 5 failed logins from {ip} within 1 minute",
                ip=ip, user=user, timestamp=timestamp
            )
            
    # 2. Suspicious Login (New IP)
    elif event_type == 'successful_login':
        if _check_new_ip(ip):
            return generate_alert(
                alert_type="Suspicious Login",
                severity="MEDIUM",
                description=f"Successful login from new IP address: {ip}",
                ip=ip, user=user, timestamp=timestamp
            )

    # 3. Privilege Escalation (Sudo usage)
    if event_type == 'sudo_usage' or 'sudo:' in raw_log or 'COMMAND=' in raw_log:
        return generate_alert(
            alert_type="Privilege Escalation",
            severity="HIGH",
            description=f"Sudo usage detected for user {user}",
            ip=ip, user=user, timestamp=timestamp
        )

    return None

def _check_brute_force(ip):
    if not ip: return False
    
    current_time = time.time()
    if ip not in failed_logins:
        failed_logins[ip] = []
        
    failed_logins[ip].append(current_time)
    
    # Remove timestamps older than 60 seconds
    failed_logins[ip] = [t for t in failed_logins[ip] if current_time - t <= 60]
    
    # If more than 5 failed logins (e.g. 6) within 1 minute
    if len(failed_logins[ip]) > 5:
        # Clear the tracking for this IP to prevent a flood of continuous alerts
        failed_logins[ip] = []
        return True
        
    return False

def _check_new_ip(ip):
    if not ip: return False
    
    if ip not in known_ips:
        known_ips.add(ip)
        return True
    return False
