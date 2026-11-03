import os
import time

from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

print("API key loaded:", bool(api_key))
print("Model:", os.getenv("GEMINI_MODEL"))

if not api_key:
    raise RuntimeError("GEMINI_API_KEY is missing")

print("Creating Gemini client...")

client = genai.Client(
    api_key=api_key,
    http_options={
        "api_version": "v1",
        "timeout": 30000,
    },
)

print("Client created.")
print("Sending request...")

start = time.time()

try:
    response = client.models.generate_content(
        model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
        contents="Reply with exactly: PATCHPILOT_OK",
    )

    print(f"Completed in {time.time() - start:.2f} seconds")
    print("Gemini response:")
    print(response.text)

except Exception as e:
    print(f"FAILED after {time.time() - start:.2f} seconds")
    print(type(e).__name__)
    print(str(e))