// Provides background cross-origin bridge communication handling logic
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "evaluateTextData") {
    fetch("http://localhost:5000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: request.text,
        url: sender.tab ? sender.tab.url : "Unknown Web Target",
        app: "Browser Extension Watcher"
      })
    })
    .then(response => response.json())
    .then(data => sendResponse({ success: true, payload: data }))
    .catch(err => sendResponse({ success: false, error: err.message }));
    
    return true; // Asynchronous message response allocation configuration
  }
});