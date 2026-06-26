import re
from flask import Flask, render_template, request

app = Flask(__name__)

# Home Page
@app.route("/")
def home():
    return render_template("index.html")

# Scanner Page
@app.route("/scanner")
def scanner():
    return render_template("scanner.html")


# Scan URL
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form["url"].strip()

    risk = 0
    reasons = []

    # HTTPS Check
    if not url.startswith("https://"):
        risk += 25
        reasons.append("Website is not using HTTPS")

    # URL Length
    if len(url) > 60:
        risk += 10
        reasons.append("URL is unusually long")

    # @ Symbol
    if "@" in url:
        risk += 20
        reasons.append("Contains @ symbol")

    # Too Many Dots
    if url.count(".") > 3:
        risk += 10
        reasons.append("Too many subdomains detected")

    # Extra //
    if "//" in url[8:]:
        risk += 10
        reasons.append("Contains extra //")

    # Hyphen
    if "-" in url:
        risk += 5
        reasons.append("Hyphen found in URL")

    # IP Address
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        risk += 30
        reasons.append("IP address detected")

    # Short URL
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "cutt.ly"
    ]

    for site in shorteners:
        if site in url.lower():
            risk += 20
            reasons.append("Shortened URL detected")
            break

    # Suspicious Keywords
    keywords = [
        "login",
        "verify",
        "bank",
        "secure",
        "update",
        "account",
        "payment",
        "wallet",
        "signin"
    ]

    for word in keywords:
        if word in url.lower():
            risk += 8
            reasons.append(f"Suspicious keyword: {word}")

    if risk > 100:
        risk = 100

    if risk >= 70:
        status = "🔴 High Risk (Possible Phishing)"
    elif risk >= 40:
        status = "🟡 Medium Risk"
    else:
        status = "🟢 Safe"

    return render_template(
        "result.html",
        url=url,
        risk=risk,
        status=status,
        reasons=reasons
    )


# Dashboard
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# About
@app.route("/about")
def about():
    return render_template("about.html")


# Security Tips
@app.route("/tips")
def tips():
    return render_template("tips.html")

# Contact
@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/developer")
def developer():
    return render_template("developer.html")

if __name__ == "__main__":
    app.run(debug=True)