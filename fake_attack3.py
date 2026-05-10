from database.connection import insert_log
from datetime import datetime, timedelta
import random

# Define attack types
attack_types = ["PORT_SCAN", "BRUTE_FORCE", "FAKE_ATTACK"]

# Start time for logs
start_time = datetime.utcnow()

for i in range(20):
    attack_type = random.choice(attack_types)  # randomly pick one attack type
    log = {
        "timestamp": (start_time + timedelta(seconds=i*30)).isoformat(),  # spaced by 30 sec
        "event": attack_type,
        "severity": random.choice(["LOW", "MEDIUM", "HIGH"]),
        "source_ip": f"192.168.1.{100 + (i%5)}",  # 5 different IPs cycling
        "destination_ip": f"192.168.1.{50 + (i%3)}",  # 3 target IPs cycling
        "user": f"user{i%3 + 1}",  # 3 different users
        "description": f"Simulated {attack_type} log #{i+1}"
    }
    inserted_id = insert_log(log)
    print(f"Inserted log {i+1} | ID: {inserted_id} | Type: {attack_type}")
