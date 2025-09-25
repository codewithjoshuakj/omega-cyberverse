async function checkURL() {
  const url = document.getElementById("urlInput").value.trim();
  const resultDiv = document.getElementById("result");
  const historyBody = document.getElementById("historyBody");

  if (!url) {
    resultDiv.style.display = "block";
    resultDiv.textContent = "⚠️ Please enter a URL first!";
    resultDiv.className = "result malicious";
    return;
  }

  // Loading state
  resultDiv.style.display = "block";
  resultDiv.textContent = "⏳ Checking...";
  resultDiv.className = "result";

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();

    let row = document.createElement("tr");
    row.innerHTML = `
      <td>${url}</td>
      <td class="${data.prediction}">${data.prediction.toUpperCase()}</td>
      <td>${data.confidence}%</td>
    `;
    historyBody.prepend(row); // latest on top

    if (data.prediction === "malicious") {
      resultDiv.textContent = `🚨 Malicious URL detected! (Confidence: ${data.confidence}%)`;
      resultDiv.className = "result malicious";
    } else {
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
