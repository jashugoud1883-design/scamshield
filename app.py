from flask import Flask, render_template, request
import sqlite3
import re
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
DB_PATH = Path(__file__).with_name("scamshield.db")

# Rule-based educational demo. This is not a guarantee that a message is safe or fraudulent.
RULES = [
    ("Urgent pressure", re.compile(r"\b(urgent|immediately|within \d+ minutes?|act now|last chance|expires today|account.{0,20}(blocked|suspended|closed))\b", re.I), 2,
     "The message pressures you to act quickly or threatens an account problem."),
    ("OTP / password request", re.compile(r"\b(otp|one[- ]time password|password|pin|cvv|verification code)\b", re.I), 3,
     "It mentions sensitive authentication details. Never share an OTP, PIN, password, or CVV with someone who contacts you."),
    ("Unexpected prize or reward", re.compile(r"\b(you (have )?won|winner|congratulations|claim (your )?(prize|reward)|free gift|cash prize|lottery)\b", re.I), 2,
     "Unexpected prizes and rewards are commonly used to lure people into scams."),
    ("Money / payment pressure", re.compile(r"\b(pay now|transfer money|send money|processing fee|pay a fee|refund pending|payment failed)\b", re.I), 2,
     "The message requests or pressures a financial action. Verify independently before paying."),
    ("Sensitive information request", re.compile(r"\b(bank details|card details|aadhaar|social security|account number|personal details)\b", re.I), 2,
     "It may be trying to collect personal or financial information."),
    ("Suspicious link pattern", re.compile(r"https?://|www\.", re.I), 1,
     "The message contains a link. A link alone does not prove a scam; inspect the domain carefully and avoid unexpected links."),
    ("Impersonation language", re.compile(r"\b(bank support|customer care|verify your account|kyc update|income tax refund|parcel held|delivery failed)\b", re.I), 1,
     "Scammers may impersonate trusted organizations or services.")
]

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                message TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings TEXT NOT NULL
            )
        """)
        conn.commit()

def analyze_message(message):
    findings = []
    score = 0
    for name, pattern, points, explanation in RULES:
        if pattern.search(message):
            findings.append({"name": name, "explanation": explanation, "points": points})
            score += points

    # Slight extra weight when the message contains multiple independent warning signs.
    if len(findings) >= 3:
        score += 1

    if score >= 6:
        risk = "High"
    elif score >= 3:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append({
            "name": "No common warning signs detected",
            "explanation": "This message did not match the patterns in this demo. That does not prove it is legitimate.",
            "points": 0
        })

    tips = []
    if any("OTP / password" == f["name"] for f in findings):
        tips.append("Never share OTPs, passwords, PINs, or CVVs.")
    if any("Suspicious link pattern" == f["name"] for f in findings):
        tips.append("Do not open unexpected links. Visit the official website by typing its address yourself.")
    if any(f["name"] in ("Unexpected prize or reward", "Money / payment pressure") for f in findings):
        tips.append("Do not pay a fee to claim an unexpected prize or refund.")
    tips.append("Verify the message using an official app, website, or phone number you find independently.")
    tips.append("If you already shared financial details, contact your bank promptly.")

    return risk, score, findings, list(dict.fromkeys(tips))

def save_analysis(message, risk, score, findings):
    summary = " | ".join(f["name"] for f in findings)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO analyses (created_at, message, risk, score, findings) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%d %b %Y, %I:%M %p"), message, risk, score, summary)
        )
        conn.commit()

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    message = ""
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            risk, score, findings, tips = analyze_message(message[:5000])
            save_analysis(message[:5000], risk, score, findings)
            result = {"risk": risk, "score": score, "findings": findings, "tips": tips}
        else:
            result = {"error": "Please paste a message before analyzing."}

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        history = conn.execute(
            "SELECT id, created_at, message, risk, score, findings FROM analyses ORDER BY id DESC LIMIT 8"
        ).fetchall()
    return render_template("index.html", result=result, message=message, history=history)

@app.route("/clear-history", methods=["POST"])
def clear_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM analyses")
        conn.commit()
    return render_template("index.html", result={"notice": "Analysis history cleared."}, message="", history=[])

init_db()

if __name__ == "__main__":
    app.run(debug=True)
