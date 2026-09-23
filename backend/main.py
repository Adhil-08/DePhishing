import sys
import os
import re

# Allow Python to access the main project directory
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from url_engine.url_analyzer import analyze_url


# ---------------------------------------------------------
# APP CONFIGURATION
# ---------------------------------------------------------

app = FastAPI(
    title="CyberSleuth API",
    description="Backend API for the CyberSleuth phishing detection system",
    version="1.0.0"
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# REQUEST MODEL
# ---------------------------------------------------------

class AnalyzeRequest(BaseModel):
    input: str


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def is_url(text: str) -> bool:
    """
    Checks whether the input looks like a URL.
    """

    text = text.strip()

    # Accept URLs with or without http/https
    pattern = r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$"

    return bool(re.match(pattern, text))


# ---------------------------------------------------------
# HOME ROUTE
# ---------------------------------------------------------

@app.get("/")
def home():

    return {
        "message": "CyberSleuth backend is running!"
    }


# ---------------------------------------------------------
# MAIN ANALYSIS ROUTE
# ---------------------------------------------------------

@app.post("/analyze")
def analyze(data: AnalyzeRequest):

    user_input = data.input.strip()

    # Empty input
    if not user_input:

        return {
            "error": "Input cannot be empty"
        }


    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    if is_url(user_input):

        result = analyze_url(user_input)

        return {
            "input": user_input,
            "type": "url",
            "url_analysis": result
        }


    # -----------------------------------------------------
    # MESSAGE ANALYSIS
    # -----------------------------------------------------

    else:

        return {
            "input": user_input,
            "type": "message",
            "message_analysis": {
                "status": "pending",
                "message": "LLM analysis will be connected here."
            }
        }