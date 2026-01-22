from flask import Flask, request, render_template
import joblib
import re

from rules import apply_rules
from db import init_db, log_email, fetch_logs

app = Flask(__name__)

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

init_db()

LABEL_MAP = {
    2: "NECESSARY",
    1: "NON-ESSENTIAL",
    0: "MALICIOUS"
}

def clean(text):
    return re.sub(r"[^a-z0-9\s]", " ", text.lower())

@app.route("/incoming", methods=["POST"])
def incoming():
    subject = request.form.get("subject", "")
    body = request.form.get("body-plain", "")
    text = clean(subject + " " + body)

    # 1️⃣ RULES FIRST
    rule_result, rule_reason = apply_rules(text)
    if rule_result is not None:
        category = LABEL_MAP[rule_result]
        log_email(subject, category, rule_reason)
        return category, 200

    # 2️⃣ ML FALLBACK
    vec = vectorizer.transform([text])
    pred = model.predict(vec)[0]

    category = LABEL_MAP[pred]
    log_email(subject, category, "ML classification")

    return category, 200

@app.route("/logs")
def logs():
    return render_template("logs.html", logs=fetch_logs())

@app.route("/")
def home():
    return "Enterprise Email Filter Running"

if __name__ == "__main__":
    app.run(port=5000)
