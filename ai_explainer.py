import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"

def explain_with_ai(email_text, indicators):
    prompt = f"""Email phishing indicators: {indicators}. Explain in 2 sentences why this is phishing."""

    payload = {
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 80, "temperature": 0.3}
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=30)
    result = response.json()

    return result["response"]

def ai_explain(extracted_data, analysis_result):
    indicators = "\n".join(f"- {r}" for r in analysis_result["reasons"])
    email_text = extracted_data.get("headers", "")[:1500]
    
    print("🔎 Generating AI explanation...")
    try:
        explanation = explain_with_ai(email_text, indicators)
    except Exception as e:
        explanation = f"AI explanation unavailable: {str(e)}"
    
    with open("report.txt", "a") as f:
        f.write("\n\n" + explanation)
    
    print("✅ AI explanation added to report")