# Database interaction module for Mini SIEM
from .connection import insert_log, insert_alert, get_alerts, get_logs, insert_blocked_ip, is_ip_blocked, get_connection

__all__ = [
    'insert_log',
    'insert_alert',
    'get_alerts',
    'get_logs',
    'insert_blocked_ip',
    'is_ip_blocked',
    'get_connection'
]

