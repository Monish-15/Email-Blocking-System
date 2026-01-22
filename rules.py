import re

def apply_rules(text):
    text = text.lower()

    # Malicious patterns
    if re.search(r"http[s]?://|www\.", text) and any(
        w in text for w in ["verify", "suspended", "urgent", "confirm"]
    ):
        return 0, "Phishing link detected"

    # OTP / critical alerts
    if re.search(r"\b\d{4,6}\b", text):
        return 2, "OTP or security code detected"

    # Marketing / non-essential
    if any(w in text for w in [
        "unsubscribe",
        "newsletter",
        "we are excited",
        "introducing",
        "promotion",
        "special announcement",
        "mailing list"
    ]):
        return 1, "Promotional or non-essential content"

    return None, "No rule matched"
