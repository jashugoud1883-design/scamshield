SCAMSHIELD — SUSPICIOUS MESSAGE ANALYZER
========================================

FEATURES
- Paste and analyze a message in a web interface.
- Rule-based detection of urgency, OTP/password mentions, unexpected prizes,
  payment pressure, personal-data requests, URLs, and impersonation language.
- Risk category, score, explanations, and safe next steps.
- SQLite analysis history and a clear-history button.
- Demo-message buttons for a quick expo presentation.

REQUIREMENTS
- Python 3.10 or newer recommended.
- Internet connection only if you need to install Flask for the first time.

WINDOWS SETUP
1. Extract ScamShield.zip to a folder.
2. Open that folder in File Explorer.
3. Click the address bar, type cmd, and press Enter.
4. Run:
       py -m venv .venv
       .venv\Scripts\activate
       py -m pip install -r requirements.txt
       py app.py
   If the `py` command does not work, try `python` instead.
5. Open this address in your browser:
       http://127.0.0.1:5000
6. Keep the terminal open while demonstrating. Press Ctrl+C in the terminal to stop.

FILES
- app.py: Flask server, rule-based analyzer, SQLite logic
- templates/index.html: web interface
- requirements.txt: Flask dependency
- scamshield.db: created automatically when the app starts

IMPORTANT
- This is a rule-based educational prototype, not a trained ML model.
- Risk score is a heuristic, not a probability.
- It does not visit or verify URLs or use live threat intelligence.
- A low risk result does not prove a message is safe.
- Use fictional messages in the expo demo. Never paste real OTPs, passwords,
  or sensitive personal information.
