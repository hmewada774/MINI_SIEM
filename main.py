import sys
import os

# Add the current directory to path if needed for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from collector import start_collector
from parser import parse_log
from database import insert_log
from detection import analyze_event
from response import trigger_response
from dashboard import start_dashboard
from utils import setup_logging

def main():
    print("Starting Mini SIEM...")
    setup_logging()
    
    # Initialization sequence
    # 1. Initialize database connections
    # 2. Start Web Dashboard
    print("Starting dashboard...")
    start_dashboard()
    
    # 3. Start Log Collector
    print("Starting collector...")
    start_collector()
    
    print("Mini SIEM is running.")

if __name__ == "__main__":
    main()
