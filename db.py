import sqlite3
from datetime import datetime

DB_NAME = "emails.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            sender TEXT,
            category TEXT,
            reasoning TEXT,
            action TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_email(subject, sender, category, reasoning, action):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (subject, sender, category, reasoning, action, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (subject, sender, category, reasoning, action, datetime.now())
    )
    conn.commit()
    conn.close()

def fetch_logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows
