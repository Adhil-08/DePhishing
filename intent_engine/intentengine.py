import os
from dotenv import load_dotenv
from openrouter import OpenRouter


# -----------------------------------------
# 1. Load API key from .env
# -----------------------------------------

load_dotenv()

api_key = os.getenv("OPENROUTER_API_KEY")

if not api_key:
    print("❌ API key not found!")
    print("Make sure your .env file contains:")
    print("OPENROUTER_API_KEY=your_api_key")
    exit()


# -----------------------------------------
# 2. Create OpenRouter client
# -----------------------------------------

client = OpenRouter(api_key=api_key)


# -----------------------------------------
# 3. Get message from user
# -----------------------------------------

message = input("\nEnter the message to analyze:\n")


# -----------------------------------------
# 4. Instructions for the AI
# -----------------------------------------

prompt = """
You are an AI phishing-message analysis engine.

Analyze the provided message for these six indicators:

1. Urgency
2. Threat
3. Credential Request
4. Financial Context
5. Impersonation
6. Social Engineering

Also determine an overall Risk Level.


Use ONLY these values:

Risk Level:
LOW / MEDIUM / HIGH

Urgency:
LOW / MEDIUM / HIGH

Threat:
LOW / MEDIUM / HIGH

Credential Request:
YES / NO

Financial Context:
YES / NO

Impersonation:
NO / POSSIBLE / YES

Social Engineering:
LOW / MEDIUM / HIGH


RETURN THE RESULT IN EXACTLY THIS FORMAT:


PHISHING ANALYSIS

Risk Level: [LOW/MEDIUM/HIGH]

Urgency: [LOW/MEDIUM/HIGH]
Threat: [LOW/MEDIUM/HIGH]
Credential Request: [YES/NO]
Financial Context: [YES/NO]
Impersonation: [NO/POSSIBLE/YES]
Social Engineering: [LOW/MEDIUM/HIGH]

Why it was flagged:
• [Short reason based on the message]
• [Short reason based on the message]
• [Short reason based on the message]

Recommended Action:
[Symbol] [One short, practical safety recommendation]


RULES:

- Do NOT add extra analysis sections.
- Do NOT explain every indicator separately.
- Keep "Why it was flagged" to 2-4 short bullet points.
- Base the reasons ONLY on evidence present in the message.
- Do not invent links, organizations, requests, or details that are not present.
- Keep the recommended action short and practical.
- Do not use markdown tables.
- Do not change the order of the fields.
- Do not add a separate conclusion.

SYMBOL RULES:

- If Risk Level is HIGH, begin Recommended Action with: ⚠️
- If Risk Level is MEDIUM, begin Recommended Action with: ⚠️
- If Risk Level is LOW, begin Recommended Action with: ✓

Put the symbol on the SAME LINE as the recommendation.
"""


# -----------------------------------------
# 5. Send message to OpenRouter
# -----------------------------------------

try:

    response = client.chat.send(
        model="openai/gpt-4o-mini",

        messages=[
            {
                "role": "system",
                "content": prompt
            },
            {
                "role": "user",
                "content": message
            }
        ]
    )


    # -----------------------------------------
    # 6. Display result
    # -----------------------------------------

    print("\n")
    print("=" * 55)
    print("                 PHISHING ANALYSIS")
    print("=" * 55)

    print(response.choices[0].message.content)

    print("=" * 55)


# -----------------------------------------
# 7. Handle errors
# -----------------------------------------

except Exception as e:

    print("\n❌ Analysis failed!")
    print("Error:", e)
    