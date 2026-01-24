import re

OTP_PATTERN = r"\b\d{4,6}\b"

MALICIOUS_KEYWORDS = [
    "verify immediately",
    "account suspended",
    "account suspension",
    "unusual activity",
    "unauthorized access",
    "confirm your identity",
    "reset your password",
    "click immediately",
    "urgent action required",
    "your account will be closed",
    "security verification failed",
    "this was not you",
    "suspicious sign-in",
    "restore access now"
]

NECESSARY_KEYWORDS = [
    "action required",
    "approval required",
    "please approve",
    "please review",
    "deadline",
    "due by",
    "respond by",
    "meeting request",
    "meeting scheduled",
    "calendar invite",
    "incident reported",
    "system outage",
    "access request",
    "access granted",
    "security update",
    "password changed",
    "account updated",
    "otp",
    "one-time password",
    "verification code"
]

NON_ESSENTIAL_KEYWORDS = [
    "newsletter",
    "update",
    "announcement",
    "promotion",
    "offer",
    "discount",
    "sale",
    "marketing",
    "webinar",
    "event invitation",
    "thank you for subscribing",
    "community update",
    "survey",
    "release notes",
    "blog"
]

def apply_rules(text):
    text = text.lower()

    if ("otp" in text or "one-time password" in text) and re.search(OTP_PATTERN, text):
        return "NECESSARY", "OTP detected", "Security verification"

    if any(word in text for word in MALICIOUS_KEYWORDS):
        return "MALICIOUS", "Malicious intent detected", "Blocked"

    if any(word in text for word in NECESSARY_KEYWORDS):
        return "NECESSARY", "Action required email", "Review and act"

    if any(word in text for word in NON_ESSENTIAL_KEYWORDS):
        return "NON-ESSENTIAL", "Informational email", "No action required"

    return None, None, None
