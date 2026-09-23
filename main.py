from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

# Import your URL Engine analyzer module
from url_engine.url_analyzer import analyze_url

app = FastAPI(title="DePhish Backend API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalysisRequest(BaseModel):
    message: str = ""
    url: str = ""

def analyze_intent(text: str) -> dict:
    score = 0
    indicators = []
    evidence = []
    
    text_lower = text.lower()
    
    if any(word in text_lower for word in ["urgent", "immediately", "24 hours", "30 minutes", "suspended", "action required"]):
        score += 30
        indicators.append("High Urgency Language")
        evidence.append("Message creates artificial time pressure or panic")
        
    if any(word in text_lower for word in ["password", "otp", "verify", "account", "login", "pin"]):
        score += 25
        indicators.append("Credential Harvest Trigger")
        evidence.append("Message explicitly requests security credentials or verification")
        
    if any(word in text_lower for word in ["sbi", "bank", "reward", "refund", "amount", "transaction", "card"]):
        score += 20
        indicators.append("Financial / Brand Context")
        evidence.append("Message targets financial services or brand impersonation")

    return {
        "score": min(score, 100),
        "indicators": indicators,
        "evidence": evidence
    }

@app.post("/api/analyze")
async def analyze_payload(request: AnalysisRequest):
    # Extract text/URL input
    input_text = request.message or request.url
    
    # Extract URL if present inside message
    target_url = request.url
    if not target_url and input_text:
        extracted = re.findall(r'https?://[^\s]+', input_text)
        if extracted:
            target_url = extracted[0]

    # Run Member 3's URL Security Engine
    url_res = {"score": 0, "indicators": [], "evidence": []}
    if target_url:
        try:
            raw_url_res = analyze_url(target_url)
            # Map url_score -> score for consistent key naming
            url_res = {
                "score": raw_url_res.get("url_score", raw_url_res.get("score", 0)),
                "indicators": raw_url_res.get("indicators", []),
                "evidence": raw_url_res.get("evidence", [])
            }
        except Exception as e:
            url_res["evidence"].append(f"URL analysis warning: {str(e)}")

    # Run Intent Analysis
    intent_res = analyze_intent(input_text)

    # Calculate Fused Dual-Engine Risk Score
    url_score = url_res.get("score", 0)
    intent_score = intent_res.get("score", 0)
    
    fused_score = max(url_score, intent_score)
    if url_score >= 30 and intent_score >= 30:
        fused_score = min(fused_score + 20, 100)

    # Aggregate All URL Engine + Intent Engine Findings
    all_indicators = list(dict.fromkeys(url_res.get("indicators", []) + intent_res.get("indicators", [])))
    all_evidence = list(dict.fromkeys(url_res.get("evidence", []) + intent_res.get("evidence", [])))

    # Determine Threat Level
    if fused_score >= 65:
        risk_level = "HIGH THREAT LEVEL"
        recommendation = "CRITICAL: High-risk phishing detected. Do not open links or share sensitive credentials."
    elif fused_score >= 35:
        risk_level = "MEDIUM THREAT LEVEL"
        recommendation = "WARNING: Suspicious indicators detected. Exercise caution before proceeding."
    else:
        risk_level = "LOW THREAT LEVEL"
        recommendation = "SAFE: No significant threat patterns detected."

    return {
        "score": fused_score,
        "risk_score": fused_score,
        "risk_level": risk_level,
        "url_analyzed": target_url,
        "indicators": all_indicators,
        "evidence": all_evidence,
        "recommendation": recommendation
    }
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Serve index.html on root path '/'
@app.get("/")
async def read_index():
    return FileResponse("frontend/index.html")

# Mount static directory for CSS/JS
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
