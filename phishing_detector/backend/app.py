from flask import Flask, request, jsonify
import pickle
import re
import pandas as pd
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load trained ML model
with open("url_model.pkl", "rb") as f:
    model = pickle.load(f)

# Known safe TLDs
SAFE_TLDS = [".com", ".org", ".edu", ".in", ".net", ".gov"]
# Suspicious words commonly seen in phishing
MALICIOUS_WORDS = ["login", "secure", "update", "bank", "verify", "account", "password"]
# Common brand names to check for typosquatting
BRAND_NAMES = ["google", "paypal", "microsoft", "amazon", "facebook", "apple"]

# ---- Feature Extraction ----
def extract_features(url):
    return {
        "length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(not c.isalnum() for c in url),
        "num_subdomains": url.count('.'),
        "has_https": int(url.startswith("https")),
        "has_ip": int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
        "has_suspicious_words": int(any(w in url.lower() for w in MALICIOUS_WORDS))
    }

# ---- Check for typosquatting (brands with numbers/extra chars) ----
def looks_like_typosquat(url):
    for brand in BRAND_NAMES:
        # If brand is inside URL but altered with digits (ex: goog1e, paypa1)
        pattern = re.sub(r"[aeiou]", "[aeiou0-9]", brand)  # allow vowels swapped with digits
        if re.search(pattern, url):
            # Detect suspicious digit substitution
            if any(char.isdigit() for char in url):
                return True
    return False

# ---- Rule-based safety check ----
def rule_based_check(url):
    url = url.lower().strip()

    # Rule 0: Localhost testing (always safe for dev)
    if "127.0.0.1" in url or "localhost" in url:
        return "safe", 100.0

    # Rule 1: Must start with http/https/www
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("www.")):
        return "malicious", 100.0

    # Rule 2: Must end with a known safe TLD
    if not any(url.endswith(tld) for tld in SAFE_TLDS):
        return "malicious", 100.0

    # Rule 3: Typosquatting check
    if looks_like_typosquat(url):
        return "malicious", 100.0

    # Rule 4: If https → always safe
    if url.startswith("https://"):
        return "safe", 100.0

    # Rule 5: If www + known TLD → safe
    if url.startswith("www.") and any(url.endswith(tld) for tld in SAFE_TLDS):
        return "safe", 100.0

    return None, None  # let ML decide

# ---- API Route ----
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()

    # Apply strict rules first
    rule_result, rule_conf = rule_based_check(url)
    if rule_result:
        return jsonify({
            "url": url,
            "prediction": rule_result,
            "confidence": rule_conf,
            "features": {}
        })

    # ML fallback
    features = extract_features(url)
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    prob = model.predict_proba(df)[0][prediction] * 100

    result = "malicious" if prediction == 1 else "safe"

    return jsonify({
        "url": url,
        "prediction": result,
        "confidence": round(float(prob), 2),
        "features": features
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
