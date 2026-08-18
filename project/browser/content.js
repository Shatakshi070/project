// Intercepts input submission vectors inside target web application boundaries
document.addEventListener("keydown", function(event) {
  const target = event.target;
  const isInputContainer = target.tagName === "TEXTAREA" || 
                           target.getAttribute("contenteditable") === "true" || 
                           target.role === "textbox";
                           
  if (isInputContainer && event.key === "Enter" && !event.shiftKey) {
    const textContext = target.value || target.innerText || "";
    
    if (textContext.trim().length > 8) { 
      event.preventDefault();
      event.stopPropagation();
      
      chrome.runtime.sendMessage({ 
        action: "evaluateTextData", 
        text: textContext 
      }, (response) => {
        if (response && response.success && response.payload.status === "sanitized") {
          // Replace raw contents inside active target nodes before event submission runs
          if (target.value !== undefined) {
            target.value = response.payload.masked_text;
          } else {
            target.innerText = response.payload.masked_text;
          }
          alert(`[Security Alert]: Sensitive data elements identified and masked (${response.payload.findings_count} objects detected).`);
        }
      });
    }
  }
}, true);