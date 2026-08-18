import sqlite3
from datetime import datetime

DB_NAME = "audit_log.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            file_name TEXT,
            file_type TEXT,
            source_app TEXT,
            destination_url TEXT,
            findings_count INTEGER,
            detected_types TEXT,
            action_status TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(file_name: str, file_type: str, source_app: str, destination_url: str, findings_count: int, detected_types: list, action_status: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, file_name, file_type, source_app, destination_url, findings_count, detected_types, action_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        file_name,
        file_type,
        source_app,
        destination_url,
        findings_count,
        ", ".join(detected_types) if detected_types else "None",
        action_status
    ))
    conn.commit()
    conn.close()