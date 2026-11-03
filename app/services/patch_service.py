import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not configured.")

client = genai.Client(
    api_key=GEMINI_API_KEY,
    http_options={
        "api_version": "v1",
        "timeout": 30000,
    },
)


def generate_patch(
    vulnerability: dict[str, Any],
    analysis: dict[str, Any],
    repository_path: str,
) -> dict[str, Any]:

    file_path = vulnerability.get("file", "")
    path = Path(file_path)

    # Resolve file inside repository if absolute path is unavailable.
    if not path.exists():
        candidate = Path(repository_path) / str(file_path)

        if candidate.exists():
            path = candidate
        else:
            filename = Path(str(file_path)).name
            matches = list(Path(repository_path).rglob(filename))

            if not matches:
                raise FileNotFoundError(
                    f"Source file could not be found: {file_path}"
                )

            path = matches[0]

    try:
        source_code = path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise RuntimeError(
            f"Could not read source file: {exc}"
        ) from exc

    prompt = f"""
You are PatchPilot AI, an expert secure-code remediation engineer.

Generate a MINIMAL and SAFE patch for the vulnerability below.

The goal is to fix ONLY the identified security issue while preserving
existing application behavior.

VULNERABILITY
=============
ID: {vulnerability.get("id")}
Rule: {vulnerability.get("rule_id")}
Severity: {vulnerability.get("severity")}
Risk: {vulnerability.get("risk")}
Risk Score: {vulnerability.get("risk_score")}

File:
{path}

VULNERABILITY LINE:
{vulnerability.get("line")}

STATIC ANALYSIS:
{vulnerability.get("message", "")}

AI SECURITY ANALYSIS
====================
Title:
{analysis.get("title")}

Root Cause:
{analysis.get("root_cause")}

Impact:
{analysis.get("impact")}

Remediation:
{analysis.get("remediation")}

Patch Strategy:
{analysis.get("patch_strategy")}

SOURCE CODE
===========
{source_code}

PATCH REQUIREMENTS
==================
1. Fix the identified vulnerability.
2. Make the smallest reasonable change.
3. Preserve existing functionality.
4. Do not refactor unrelated code.
5. Do not modify dependencies unless absolutely necessary.
6. Do not remove security checks.
7. Do not introduce a new vulnerability.
8. The old_code must be copied EXACTLY from the source.
9. The new_code must be valid code replacing old_code.
10. old_code should contain only the smallest useful block required
    for the fix.
11. If the vulnerability cannot be safely patched with the available
    source, say so instead of guessing.
"""

    schema = {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["PATCH_READY", "PATCH_NOT_SAFE"],
            },
            "file": {
                "type": "string",
            },
            "explanation": {
                "type": "string",
            },
            "old_code": {
                "type": "string",
            },
            "new_code": {
                "type": "string",
            },
            "confidence": {
                "type": "string",
                "enum": ["HIGH", "MEDIUM", "LOW"],
            },
            "safety_notes": {
                "type": "string",
            },
        },
        "required": [
            "status",
            "file",
            "explanation",
            "old_code",
            "new_code",
            "confidence",
            "safety_notes",
        ],
    }

    try:
        interaction = client.interactions.create(
            model=GEMINI_MODEL,
            input=prompt,
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": schema,
            },
        )

        result = json.loads(interaction.output_text)

    except Exception as exc:
        raise RuntimeError(
            f"Gemini patch generation failed: {exc}"
        ) from exc

    if result["status"] == "PATCH_READY":
        if not result["old_code"].strip():
            raise RuntimeError(
                "Gemini returned an empty old_code."
            )

        if not result["new_code"].strip():
            raise RuntimeError(
                "Gemini returned an empty new_code."
            )

        occurrences = source_code.count(
            result["old_code"]
        )

        if occurrences != 1:
            raise RuntimeError(
                "Patch safety check failed: old_code occurs "
                f"{occurrences} times in the source file."
            )

    return {
        "vulnerability_id": vulnerability.get("id"),
        "file": str(path),
        "status": result["status"],
        "explanation": result["explanation"],
        "old_code": result["old_code"],
        "new_code": result["new_code"],
        "confidence": result["confidence"],
        "safety_notes": result["safety_notes"],
        "model": GEMINI_MODEL,
    }