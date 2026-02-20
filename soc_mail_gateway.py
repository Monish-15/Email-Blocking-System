from flask import Flask, request
import sqlite3
import re
import datetime
import requests
import json
import os

app = Flask(__name__)
DB_NAME = "soc_logs.db"

# =========================================================
# DATABASE
# =========================================================

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sender TEXT,
            sender_ip TEXT,
            country TEXT,
            domain TEXT,
            urls TEXT,
            threat_score INTEGER,
            decision TEXT,
            reason TEXT,
            subject TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_event(data):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        INSERT INTO logs (
            timestamp, sender, sender_ip, country,
            domain, urls, threat_score,
            decision, reason, subject
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, data)
    conn.commit()
    conn.close()

# =========================================================
# UTILITIES
# =========================================================

def extract_urls(text):
    return re.findall(r'https?://[^\s)"]+', text)

def extract_sender_ip():
    try:
        headers = request.form.get("message-headers")
        if headers:
            headers = json.loads(headers)
            for header in headers:
                if header[0].lower() == "received":
                    match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', header[1])
                    if match:
                        return match.group(1)
    except:
        pass
    return "Unknown"

def get_geo(ip):
    try:
        if ip in ["Unknown", "0.0.0.0"]:
            return "Unknown"
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        if r.status_code == 200:
            return r.json().get("country_name", "Unknown")
    except:
        pass
    return "Unknown"

def get_domain(email):
    if "@" in email:
        return email.split("@")[1].replace(">", "").lower()
    return "unknown"

# =========================================================
# CLOUD TRUST SYSTEM
# =========================================================

TRUSTED_CLOUD_PROVIDERS = [
    "google.com", "gmail.com", "outlook.com",
    "microsoft.com", "office365.com",
    "amazonaws.com", "sendgrid.net", "mailgun.org"
]

def cloud_trust(domain):
    return any(provider in domain for provider in TRUSTED_CLOUD_PROVIDERS)

# =========================================================
# KEYWORD DEFINITIONS
# =========================================================

BUSINESS_WORDS = [
    "meeting", "discussion", "schedule", "agenda", "minutes",
    "project", "deadline", "milestone", "review", "update",
    "report", "analysis", "proposal", "presentation",
    "conference", "call", "client", "stakeholder",
    "invoice", "payment", "receipt", "quotation",
    "purchase order", "transaction", "statement",
    "refund", "billing", "tax", "expense",
    "leave", "attendance", "interview", "joining",
    "offer letter", "onboarding", "salary",
    "appraisal", "evaluation", "policy",
    "assignment", "exam", "results", "marks",
    "lab", "seminar", "research", "paper",
    "attachment", "shared file", "google drive",
    "document", "spreadsheet", "slides",
    "zoom", "teams", "calendar invite",
    "order confirmation", "shipment", "delivery",
    "tracking number", "subscription"
]

GENERIC_GREETINGS = [
    "dear customer", "valued customer", "dear user",
    "dear account holder", "dear client",
    "dear member", "dear sir", "dear madam",
    "attention customer", "greetings of the day"
]

URGENCY_WORDS = [
    "urgent", "immediately", "act now",
    "within 24 hours", "final notice",
    "last warning", "limited time",
    "expires today", "action required",
    "time sensitive", "failure to comply"
]

PHISHING_KEYWORDS = [
    "reset password", "verify account",
    "login immediately", "account suspended",
    "account locked", "confirm identity",
    "validate account", "re-authenticate",
    "update payment", "bank alert",
    "security alert", "unauthorized transaction",
    "suspicious activity", "confirm transaction",
    "click below to login", "secure your account",
    "verify your details", "update your information",
    "legal action", "account termination",
    "service suspension", "delivery failed",
    "package on hold", "you have won",
    "claim your prize"
]

HIGH_RISK_COUNTRIES = ["Russia", "Nigeria", "North Korea", "Iran"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".ru", ".tk", ".cn"]
OTP_PATTERN = r"\b\d{6}\b"

# =========================================================
# HYBRID THREAT ENGINE
# =========================================================

def hybrid_engine(text, country, domain):
    text_lower = text.lower()
    urls = extract_urls(text)
    threat_score = 0
    hard_block = False
    reasons = []

    is_trusted_cloud = cloud_trust(domain)

    # ---- Phishing scoring ----
    phishing_hits = sum(1 for k in PHISHING_KEYWORDS if k in text_lower)
    if phishing_hits >= 2:
        threat_score += 60
        reasons.append("multiple phishing indicators")
    elif phishing_hits == 1:
        threat_score += 35
        reasons.append("phishing indicator")

    # ---- Urgency scoring ----
    urgency_hits = sum(1 for u in URGENCY_WORDS if u in text_lower)
    if urgency_hits >= 2:
        threat_score += 30
        reasons.append("strong urgency")
    elif urgency_hits == 1:
        threat_score += 15
        reasons.append("urgency wording")

    # ---- Generic greeting ----
    if any(g in text_lower for g in GENERIC_GREETINGS):
        threat_score += 15
        reasons.append("generic greeting")

    # ---- Links ----
    if len(urls) == 1:
        threat_score += 10
        reasons.append("contains link")
    elif len(urls) >= 2:
        threat_score += 25
        reasons.append("multiple links")

    # ---- Numeric density ----
    if sum(c.isdigit() for c in text_lower) > 12:
        threat_score += 15
        reasons.append("high numeric density")

    # ---- Geo Risk ----
    if country in HIGH_RISK_COUNTRIES:
        threat_score += 25
        reasons.append("high-risk country")

    # ---- Suspicious TLD ----
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        threat_score += 25
        reasons.append("suspicious TLD")

    # ---- Cloud Trust Reduction ----
    if is_trusted_cloud:
        threat_score -= 30
        reasons.append("trusted cloud provider")

    # ---- Business Context Reduction ----
    business_hits = sum(1 for b in BUSINESS_WORDS if b in text_lower)
    if business_hits >= 2 and phishing_hits == 0:
        threat_score -= 30
        reasons.append("strong business context")
    elif business_hits == 1 and phishing_hits == 0:
        threat_score -= 15
        reasons.append("business context")

    # ---- OTP Reduction ----
    if re.search(OTP_PATTERN, text):
        threat_score -= 40
        reasons.append("otp detected")

    # ---- Hard Block ----
    if phishing_hits >= 1 and len(urls) >= 1 and not is_trusted_cloud:
        hard_block = True
        reasons.append("phishing + link")

    # ---- Decision ----
    if hard_block:
        return 100, "MALICIOUS", ", ".join(reasons)

    if threat_score >= 70:
        return threat_score, "MALICIOUS", ", ".join(reasons)
    elif threat_score >= 40:
        return threat_score, "NON-ESSENTIAL", ", ".join(reasons)
    else:
        return threat_score, "NECESSARY", ", ".join(reasons)

# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def home():
    return "SOC Mail Gateway Running"

@app.route("/incoming", methods=["POST"])
def incoming():
    sender = request.form.get("from", "unknown")
    subject = request.form.get("subject", "")
    body = request.form.get("body-plain", "") + " " + request.form.get("body-html", "")

    sender_ip = extract_sender_ip()
    country = get_geo(sender_ip)
    domain = get_domain(sender)

    full_text = subject + " " + body

    threat_score, decision, reason = hybrid_engine(full_text, country, domain)

    log_event((
        str(datetime.datetime.now()),
        sender,
        sender_ip,
        country,
        domain,
        ", ".join(extract_urls(full_text)),
        threat_score,
        decision,
        reason,
        subject
    ))

    return decision

@app.route("/logs")
def logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    rows = c.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    conn.close()

    html = "<h2>SOC Logs</h2><table border=1>"
    html += "<tr><th>ID</th><th>Time</th><th>Sender</th><th>IP</th><th>Country</th><th>Domain</th><th>URLs</th><th>Score</th><th>Decision</th><th>Reason</th><th>Subject</th></tr>"

    for r in rows:
        html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td><td>{r[5]}</td><td>{r[6]}</td><td>{r[7]}</td><td>{r[8]}</td><td>{r[9]}</td><td>{r[10]}</td></tr>"

    html += "</table>"
    return html

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)