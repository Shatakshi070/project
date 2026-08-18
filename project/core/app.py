from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import DataSanitizationEngine
from database import initialize_database, log_event

app = Flask(__name__)
CORS(app)  # Enables transport from browser extensions & scripts

engine = DataSanitizationEngine()
initialize_database()

# Recognized GenAI targets
GENAI_DOMAINS = ["chatgpt.com", "openai.com", "copilot.microsoft.com", "gemini.google.com", "claude.ai", "perplexity.ai"]

@app.route("/api/analyze", methods=["POST"])
def analyze_payload():
    data = request.json or {}
    raw_text = data.get("text", "")
    destination_url = data.get("url", "Unknown Target App")
    source_app = data.get("app", "Web Application Stream")
    file_name = data.get("file_name", "Inline Text Element")
    file_type = data.get("file_type", "Text String")

    # Check if target is a GenAI platform
    is_genai = any(domain in destination_url.lower() for domain in GENAI_DOMAINS)

    if not raw_text.strip():
        return jsonify({"status": "empty", "masked_text": ""}), 200

    analysis = engine.mask_text_stream(raw_text)

    status = "clean"
    if analysis["findings_count"] > 0:
        status = "sanitized_for_genai" if is_genai else "sanitized"

    # Commit audit log metrics
    log_event(
        file_name=file_name,
        file_type=file_type,
        source_app=source_app,
        destination_url=destination_url,
        findings_count=analysis["findings_count"],
        detected_types=analysis["detected_types"],
        action_status=status
    )

    return jsonify({
        "status": status,
        "is_genai_target": is_genai,
        "masked_text": analysis["masked_text"],
        "findings_count": analysis["findings_count"],
        "detected_types": analysis["detected_types"]
    }), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)