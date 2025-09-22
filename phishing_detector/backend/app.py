from flask import Flask, request, jsonify
import pickle
import re
import pandas as pd
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow frontend to call API

# Load trained model
with open("url_model.pkl", "rb") as f:
    model = pickle.load(f)

# ---- Feature Extraction ----
def extract_features(url):
    return {
        "length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(not c.isalnum() for c in url),
        "num_subdomains": url.count('.'),
        "has_https": int(url.startswith("https")),
        "has_ip": int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
        "has_suspicious_words": int(any(w in url.lower() for w in ["login","bank","secure","update"]))
    }

# ---- Prediction Route ----
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"]
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
