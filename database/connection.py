import os
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, PyMongoError
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

class MongoDBConnection:
    """Singleton class for MongoDB connection management."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            instance = super(MongoDBConnection, cls).__new__(cls)
            try:
                instance._init_connection()
                cls._instance = instance
            except Exception:
                raise
        return cls._instance

    def _init_connection(self):
        """Initialize the connection to MongoDB and set up collections."""
        mongo_uri = os.getenv("MONGO_URI")
        if not mongo_uri:
            logger.error("MONGO_URI not found in environment variables.")
            raise ValueError("MONGO_URI must be set in .env file.")
        
        try:
            # Create a client with a timeout
            self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            
            # Verify the connection by pinging the server
            self.client.admin.command('ping')
            
            # Connect to "siem_db"
            self.db = self.client["siem_db"]
            
            # Create/access collections
            self.logs = self.db["logs"]
            self.alerts = self.db["alerts"]
            self.blocked_ips = self.db["blocked_ips"]
            
            logger.info("Successfully connected to MongoDB 'siem_db'")
            
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self.client = None
            raise
        except Exception as e:
            logger.error(f"Error initializing MongoDB connection: {e}")
            self.client = None
            raise

# Global connection instance
_db_connection = None

def get_connection():
    """Retrieve the global MongoDB connection instance."""
    global _db_connection
    if _db_connection is None:
        _db_connection = MongoDBConnection()
    return _db_connection

def insert_log(log_data: dict) -> str:
    """Insert a log into the 'logs' collection."""
    try:
        conn = get_connection()
        result = conn.logs.insert_one(log_data)
        return str(result.inserted_id)
    except PyMongoError as e:
        logger.error(f"Failed to insert log: {e}")
        return None

def insert_alert(alert_data: dict) -> str:
    """Insert an alert into the 'alerts' collection."""
    try:
        conn = get_connection()
        result = conn.alerts.insert_one(alert_data)
        return str(result.inserted_id)
    except PyMongoError as e:
        logger.error(f"Failed to insert alert: {e}")
        return None

def get_alerts(query: dict = None, limit: int = 100) -> list:
    """Retrieve alerts from the 'alerts' collection based on a query."""
    try:
        conn = get_connection()
        query = query or {}
        alerts = list(conn.alerts.find(query).limit(limit))
        return alerts
    except PyMongoError as e:
        logger.error(f"Failed to retrieve alerts: {e}")
        return []

def get_logs(query: dict = None, limit: int = 100) -> list:
    """Retrieve logs from the 'logs' collection based on a query."""
    try:
        conn = get_connection()
        query = query or {}
        logs = list(conn.logs.find(query).limit(limit))
        return logs
    except PyMongoError as e:
        logger.error(f"Failed to retrieve logs: {e}")
        return []

def insert_blocked_ip(ip: str, reason: str = "") -> str:
    """Insert a blocked IP into the 'blocked_ips' collection."""
    from datetime import datetime
    try:
        conn = get_connection()
        if not is_ip_blocked(ip):
            result = conn.blocked_ips.insert_one({
                "ip": ip, 
                "reason": reason, 
                "timestamp": datetime.now().isoformat()
            })
            return str(result.inserted_id)
        return None
    except PyMongoError as e:
        logger.error(f"Failed to insert blocked IP: {e}")
        return None

def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is already in the 'blocked_ips' collection."""
    try:
        conn = get_connection()
        return conn.blocked_ips.count_documents({"ip": ip}, limit=1) > 0
    except PyMongoError as e:
        logger.error(f"Failed to check blocked IP: {e}")
        return False
