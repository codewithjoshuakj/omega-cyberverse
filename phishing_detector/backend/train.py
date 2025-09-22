import pandas as pd
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ---- Sample Dataset ----
data = {
    "url": [
        "https://google.com",
        "https://wikipedia.org",
        "https://amazon.com",
        "http://paypal-login.com",
        "http://secure-bank-login.ru",
        "http://update-account.info",
        "https://github.com",
        "https://stackoverflow.com",
        "http://malware-download.net",
        "http://free-prizes.click"
    ],
    "label": [
        "safe",
        "safe",
        "safe",
        "malicious",
        "malicious",
        "malicious",
        "safe",
        "safe",
        "malicious",
        "malicious"
    ]
}

df = pd.DataFrame(data)

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

df["features"] = df["url"].apply(extract_features)
X = pd.DataFrame(df["features"].tolist())
y = df["label"].map({"safe": 0, "malicious": 1})

# ---- Train/Test Split ----
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ---- Train Model ----
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

# ---- Evaluate ----
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# ---- Save Model ----
with open("url_model.pkl", "wb") as f:
    pickle.dump(clf, f)

print("✅ Model trained and saved as url_model.pkl")
