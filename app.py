from flask import Flask, render_template, request, session
import pickle
import re
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = "phishguard-local-demo-key"

# Existing trained model and vectorizer
with open("vectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

with open("phishing.pkl", "rb") as f:
    model = pickle.load(f)


def analyze_url(url):
    """Perform explainable URL-level security checks."""

    original = url.strip()

    normalized = (
        original
        if re.match(r"^https?://", original, re.I)
        else "http://" + original
    )

    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()

    signals = []

    # 1. URL length
    if len(original) > 75:
        signals.append(
            ("Long URL", "The URL is unusually long.")
        )
    elif len(original) > 54:
        signals.append(
            ("Moderately long URL",
             "The URL is longer than a typical short domain.")
        )

    # 2. IP address instead of domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        signals.append(
            ("IP address used",
             "The destination uses an IP address instead of a domain name.")
        )

    # 3. @ symbol
    if "@" in original:
        signals.append(
            ("'@' symbol detected",
             "The @ symbol can be abused to disguise the destination.")
        )

    # 4. HTTPS
    uses_https = parsed.scheme.lower() == "https"

    if not uses_https:
        signals.append(
            ("HTTPS not detected",
             "The submitted URL does not use HTTPS.")
        )

    # 5. Excessive subdomains
    dot_count = hostname.count(".")

    if dot_count >= 4:
        signals.append(
            ("Many subdomains",
             f"The hostname contains {dot_count} dots.")
        )

    # 6. Encoded characters
    if original.count("%") >= 3:
        signals.append(
            ("Encoded characters",
             "The URL contains several percent-encoded characters.")
        )

    # 7. Suspicious keywords
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "password",
        "credential",
        "confirm",
        "secure",
        "update"
    ]

    found_keywords = [
        word for word in suspicious_keywords
        if word in original.lower()
    ]

    if found_keywords:
        signals.append(
            ("Sensitive keywords",
             ", ".join(found_keywords[:5]))
        )

    # 8. URL shorteners
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    }

    if hostname in shorteners:
        signals.append(
            ("URL shortener",
             "A shortened URL can hide the final destination.")
        )

    return {
        "hostname": hostname or "Unknown",
        "length": len(original),
        "https": uses_https,
        "signals": signals
    }


def classify_risk(prediction, signal_count):
    """
    Simple heuristic risk label.
    This is NOT a calibrated probability.
    """

    if prediction == "bad":
        return "High", "high"

    if signal_count >= 3:
        return "Medium", "medium"

    return "Low", "low"


def signal_score(signal_count):
    """Heuristic security-signal score."""

    return min(signal_count * 20, 100)


def recommendation(prediction, risk_level):

    if prediction == "bad":
        return (
            "Avoid entering credentials or downloading files from this URL. "
            "Verify the domain through an official source before interacting with it."
        )

    if risk_level == "Medium":
        return (
            "Proceed with caution. Review the URL and verify the website "
            "through a trusted source before entering sensitive information."
        )

    return (
        "No obvious URL-level warning signals were detected. "
        "Still verify the website before entering sensitive information."
    )


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    error = None
    submitted_url = ""

    if request.method == "POST":

        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:

            error = "Please enter a URL to analyze."

        else:

            try:

                # Existing ML pipeline
                cleaned_url = re.sub(
                    r"^https?://(www\.)?",
                    "",
                    submitted_url,
                    flags=re.I
                )

                features = vectorizer.transform([cleaned_url])

                prediction = model.predict(features)[0]

                # Model confidence
                confidence = None

                if hasattr(model, "predict_proba"):

                    probabilities = model.predict_proba(features)[0]

                    confidence = round(
                        float(max(probabilities)) * 100,
                        1
                    )

                # Additional URL analysis
                analysis = analyze_url(submitted_url)

                risk_level, risk_class = classify_risk(
                    prediction,
                    len(analysis["signals"])
                )

                score = signal_score(
                    len(analysis["signals"])
                )

                result = {
                    "url": submitted_url,
                    "prediction": prediction,
                    "confidence": confidence,
                    "risk_level": risk_level,
                    "risk_class": risk_class,
                    "signal_score": score,
                    "recommendation": recommendation(
                        prediction,
                        risk_level
                    ),
                    "timestamp": datetime.now().strftime(
                        "%d %b %Y, %I:%M %p"
                    ),
                    **analysis
                }

                # Store last 5 scans in browser session
                history = session.get(
                    "scan_history",
                    []
                )

                history.insert(
                    0,
                    {
                        "url": submitted_url[:90],
                        "verdict": (
                            "Phishing"
                            if prediction == "bad"
                            else "Likely Legitimate"
                        ),
                        "confidence": confidence,
                        "risk": risk_level,
                        "time": result["timestamp"],
                        "bad": prediction == "bad"
                    }
                )

                session["scan_history"] = history[:5]

            except Exception as exc:

                error = f"Could not analyze this URL: {exc}"

    return render_template(
        "index.html",
        result=result,
        error=error,
        submitted_url=submitted_url,
        history=session.get("scan_history", [])
    )


@app.route("/clear-history", methods=["POST"])
def clear_history():

    session.pop("scan_history", None)

    return render_template(
        "index.html",
        result=None,
        error=None,
        submitted_url="",
        history=[]
    )


if __name__ == "__main__":
    app.run(debug=True)