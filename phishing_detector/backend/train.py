import pandas as pd
import random
import string
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# ---------------- Generate Synthetic Dataset ----------------
safe_domains = ["google", "amazon", "wikipedia", "github", "mit", "harvard", "stackoverflow", "microsoft", "apple", "netflix"]
safe_tlds = [".com", ".org", ".edu", ".in", ".net"]

malicious_words = ["login", "secure", "update", "bank", "verify", "account", "password"]
bad_tlds = [".xyz", ".click", ".ru", ".info", ".top"]

def random_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def generate_safe_url():
    if random.random() < 0.5:
        return f"https://{random.choice(safe_domains)}{random.choice(safe_tlds)}"
    else:
        return f"www.{random.choice(safe_domains)}{random.choice(safe_tlds)}"

def generate_malicious_url():
    if random.random() < 0.3:  # Use IP as domain
        ip = ".".join(str(random.randint(1,255)) for _ in range(4))
        return f"http://{ip}/{random.choice(malicious_words)}"
    else:
        return f"http://{random_string(6)}-{random.choice(malicious_words)}{random.choice(bad_tlds)}"

# Generate 50k safe + 50k malicious
safe_urls = [(generate_safe_url(), "safe") for _ in range(50000)]
malicious_urls = [(generate_malicious_url(), "malicious") for _ in range(50000)]

data = safe_urls + malicious_urls
random.shuffle(data)

df = pd.DataFrame(data, columns=["url", "label"])

# ---------------- Feature Extraction ----------------
def extract_features(url):
    return {
        "length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(not c.isalnum() for c in url),
        "num_subdomains": url.count('.'),
        "has_https": int(url.startswith("https")),
        "has_ip": int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
        "has_suspicious_words": int(any(w in url.lower() for w in malicious_words))
    }

df["features"] = df["url"].apply(extract_features)
X = pd.DataFrame(df["features"].tolist())
y = df["label"].map({"safe": 0, "malicious": 1})

# ---------------- Train/Test Split ----------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# ---------------- Train Model ----------------
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

# ---------------- Evaluate ----------------
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# ---------------- Save Model ----------------
with open("url_model.pkl", "wb") as f:
    pickle.dump(clf, f)

print("✅ Model trained on 100,000 synthetic URLs and saved as url_model.pkl")
