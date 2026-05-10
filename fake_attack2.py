from database.connection import insert_log
from datetime import datetime

for i in range(5):
    log = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": "PORT_SCAN",
        "severity": "HIGH",
        "source_ip": f"192.168.1.{100+i}",
        "destination_ip": "192.168.1.50",
        "user": f"tester{i+1}",
        "description": "Simulated port scan for testing"
    }
    insert_log(log)
    print(f"Inserted log from {log['source_ip']}")
