from database.connection import insert_log

log_id = insert_log({
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.50",
    "timestamp": "2026-05-10T12:00:00Z",
    "event": "FAKE_ATTACK",
    "severity": "HIGH",
    "description": "Simulated attack for testing"
})

print("Inserted fake attack log with ID:", log_id)
