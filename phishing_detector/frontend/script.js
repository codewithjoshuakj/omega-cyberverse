function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!url) {
    resultDiv.style.display = "block";
    resultDiv.textContent = "⚠️ Please enter a URL first!";
    resultDiv.className = "result malicious";
    return;
  }

  // Simple mock rules for frontend demo
  if (url.includes("paypal") || url.includes("login") || url.includes("bank")) {
    resultDiv.style.display = "block";
    resultDiv.textContent = "⚠️ Malicious URL detected!";
    resultDiv.className = "result malicious";
  } else {
    resultDiv.style.display = "block";
    resultDiv.textContent = "✅ Safe URL";
    resultDiv.className = "result safe";
  }
}
