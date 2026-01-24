from flask import Flask, request, render_template
import joblib
import re

from rules import apply_rules
from db import init_db, log_email, fetch_logs

print("SERVER FILE EXECUTED")

app = Flask(__name__)

init_db()

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

def clean(text):
    return re.sub(r"[^a-z0-9\s:/\.]", " ", text.lower())

@app.route("/")
def home():
    return "Email Classification Backend Running"

@app.route("/incoming", methods=["POST"])
def incoming():
    subject = request.form.get("subject", "")
    sender = request.form.get("from", "")
    body = request.form.get("body-plain", "")

    text = clean(subject + " " + body)

    rule_category, reasoning, action = apply_rules(text)

    if rule_category:
        category = rule_category
    else:
        vec = vectorizer.transform([text])
        pred = model.predict(vec)[0]
        category = "NECESSARY" if pred == 2 else "NON-ESSENTIAL"
        reasoning = "ML fallback classification"
        action = "Review" if pred == 2 else "No action required"

    log_email(subject, sender, category, reasoning, action)
    return category, 200

@app.route("/logs")
def logs():
    rows = fetch_logs()
    return render_template("logs.html", logs=rows)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
