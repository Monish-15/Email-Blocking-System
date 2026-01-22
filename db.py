import sqlite3

def init_db():
    conn = sqlite3.connect("emails.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            category TEXT,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def log_email(subject, category, reason):
    conn = sqlite3.connect("emails.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (subject, category, reason) VALUES (?, ?, ?)",
        (subject, category, reason)
    )
    conn.commit()
    conn.close()

def fetch_logs():
    conn = sqlite3.connect("emails.db")
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return rows
