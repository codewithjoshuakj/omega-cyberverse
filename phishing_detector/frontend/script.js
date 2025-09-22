async function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");

  if (!url) {
    resultDiv.style.display = "block";
    resultDiv.textContent = "⚠️ Please enter a URL first!";
    resultDiv.className = "result malicious";
    return;
  }

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    if (data.prediction === "malicious") {
      resultDiv.style.display = "block";
      resultDiv.textContent = `⚠️ Malicious URL detected! (Confidence: ${data.confidence}%)`;
      resultDiv.className = "result malicious";
    } else {
      resultDiv.style.display = "block";
      resultDiv.textContent = `✅ Safe URL (Confidence: ${data.confidence}%)`;
      resultDiv.className = "result safe";
    }

  } catch (error) {
    resultDiv.style.display = "block";
    resultDiv.textContent = "❌ Error connecting to backend!";
    resultDiv.className = "result malicious";
    console.error(error);
  }
}
