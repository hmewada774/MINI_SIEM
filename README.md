# 🛡️ Mini SIEM

Mini SIEM is a lightweight, modular Security Information and Event Management (SIEM) system built in Python for Linux environments. It monitors system logs in real-time, detects malicious activities using rule-based analysis, stores events in MongoDB Atlas, triggers automated responses (like blocking IPs via `iptables`), and provides a beautiful web-based dashboard for visualization.

![Mini SIEM Dashboard](./screenshot.png) *(Please place your screenshot here and name it `screenshot.png`)*

## 🚀 Features

*   **Real-Time Log Collection:** Continuously tails `/var/log/auth.log` for authentication and authorization events.
*   **Regex-Based Parser:** Extracts structured data (IP addresses, usernames, timestamps) from raw syslogs.
*   **Rule-Based Detection Engine:**
    *   **SSH Brute Force:** Detects >5 failed logins from the same IP within 1 minute.
    *   **Suspicious Logins:** Flags successful logins from previously unseen IP addresses.
    *   **Privilege Escalation:** Monitors and alerts on `sudo` command usage.
*   **Automated Incident Response:** Safely and automatically uses `iptables` to block malicious IP addresses (with built-in localhost whitelisting).
*   **MongoDB Atlas Integration:** Stores logs, alerts, and blocked IPs securely in the cloud.
*   **Dynamic Web Dashboard:** Built with Flask, Bootstrap 5, and Chart.js to provide real-time metrics, attack distribution charts, and live data tables.

## 📁 Project Structure

```text
mini_siem/
├── main.py              # Application entry point
├── start.sh             # Secure startup script (runs with sudo)
├── config.py            # Global configuration settings
├── .env                 # Environment variables (MongoDB URI)
├── requirements.txt     # Python dependencies
├── collector/           # Real-time log file tailing
├── parser/              # Regex pattern matching and extraction
├── detection/           # Analysis and threat detection rules
├── response/            # Automated alerting and iptables blocking
├── database/            # MongoDB connection and queries
└── dashboard/           # Flask web application and API endpoints
    └── templates/       # HTML/JS for the frontend UI
```

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd mini_siem
   ```

2. **Set up the Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configure MongoDB:**
   * Create an `.env` file in the root directory.
   * Add your MongoDB Atlas connection string (ensure special characters in passwords are URL-encoded):
     ```env
     MONGO_URI=mongodb+srv://<username>:<password>@cluster...
     ```

## 💻 Usage

Because the SIEM needs to read `/var/log/auth.log` and modify `iptables`, it must be run with root privileges.

**Start the SIEM:**
```bash
sudo ./start.sh
```

**Access the Dashboard:**
Open your web browser and navigate to:
```text
http://localhost:5000
```

## 🧪 Testing the SIEM

To verify that the detection and response engines are working, you can simulate a Brute Force attack. Open a new terminal window and run:

```bash
sudo python3 -c '
import time
with open("/var/log/auth.log", "a") as f:
    for i in range(10):
        f.write("May 10 13:50:00 kali sshd[12345]: Failed password for invalid user fake_attacker from 192.168.1.100 port 50000 ssh2\n")
        f.flush()
        time.sleep(0.1)
'
```

Instantly check your dashboard to see the new alerts, populated charts, and the `192.168.1.100` IP automatically blocked!

---
*Developed for Linux environments.*



