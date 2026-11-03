import json
import os
import re
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


def _redact_secrets(code: str) -> str:
    """
    Redact obvious secrets before sending source code to the model.
    """

    patterns = [
        (
            r'(?i)(api[_-]?key\s*=\s*[\'"])[^\'"]+([\'"])',
            r'\1[REDACTED]\2',
        ),
        (
            r'(?i)(secret[_-]?key\s*=\s*[\'"])[^\'"]+([\'"])',
            r'\1[REDACTED]\2',
        ),
        (
            r'(?i)(password\s*=\s*[\'"])[^\'"]+([\'"])',
            r'\1[REDACTED]\2',
        ),
        (
            r'(?i)(token\s*=\s*[\'"])[^\'"]+([\'"])',
            r'\1[REDACTED]\2',
        ),
    ]

    for pattern, replacement in patterns:
        code = re.sub(pattern, replacement, code)

    return code


def _get_code_context(
    file_path: str,
    line_number: int | None,
    context_lines: int = 10,
) -> str:
    """
    Read a small amount of source around the vulnerable line.
    """

    if not file_path:
        return "Source code unavailable."

    path = Path(file_path)

    if not path.exists() or not path.is_file():
        return "Source code unavailable."

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

        if not lines:
            return "Source code is empty."

        if line_number is None:
            start = 0
            end = min(len(lines), 30)
        else:
            target = max(1, line_number)

            start = max(0, target - 1 - context_lines)
            end = min(
                len(lines),
                target - 1 + context_lines + 1,
            )

        selected = []

        for index in range(start, end):
            selected.append(
                f"{index + 1:>4}: {lines[index]}"
            )

        return _redact_secrets("\n".join(selected))

    except OSError:
        return "Unable to read source code."


def analyze_vulnerability(
    vulnerability: dict[str, Any],
    repository_path: str | None = None,
) -> dict[str, Any]:

    file_path = vulnerability.get("file", "")
    line = vulnerability.get("line")

    # Semgrep may return an absolute path.
    # If it doesn't exist, try resolving it inside the repository.
    if repository_path and (
        not file_path or not Path(file_path).exists()
    ):
        candidate = Path(repository_path) / str(file_path)

        if candidate.exists():
            file_path = str(candidate)
        else:
            filename = Path(str(file_path)).name

            matches = list(
                Path(repository_path).rglob(filename)
            )

            if matches:
                file_path = str(matches[0])

    code_context = _get_code_context(
        file_path,
        line,
    )

    metadata = vulnerability.get("metadata", {})

    cwe = metadata.get("cwe", [])
    owasp = metadata.get("owasp", [])

    prompt = f"""
You are PatchPilot AI, an expert application security engineer.

Analyze the detected vulnerability using BOTH:
1. The static-analysis finding.
2. The actual source-code context.

Do not blindly trust the scanner message.
Reason about the code itself.

Your analysis must be technically specific and useful to a developer.

SECURITY FINDING
================
ID: {vulnerability.get("id")}
Rule ID: {vulnerability.get("rule_id")}
Severity: {vulnerability.get("severity")}
Risk: {vulnerability.get("risk")}
Risk Score: {vulnerability.get("risk_score")}

File: {file_path}
Vulnerable Line: {line}

Scanner Message:
{vulnerability.get("message", "")}

CWE:
{cwe}

OWASP:
{owasp}

SOURCE CODE
===========
{code_context}

TASK
====
Determine:

- What exactly is vulnerable?
- What is the root cause in the code?
- What could realistically happen if exploited?
- How could attacker-controlled input reach the vulnerable operation?
- What secure coding technique should replace the vulnerable pattern?
- What minimal code change should PatchPilot eventually make?
- How confident are you?

IMPORTANT SECURITY RULES
========================
- Do not claim exploitation is guaranteed.
- Do not invent application behavior that is not visible.
- Do not recommend disabling security controls.
- Prefer minimal, behavior-preserving fixes.
- Be specific to the actual code.
- If the scanner appears incorrect, say so.
- Never expose or reproduce secrets found in source code.
"""

    schema = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short vulnerability title.",
            },
            "root_cause": {
                "type": "string",
                "description": "Precise technical root cause based on the code.",
            },
            "impact": {
                "type": "string",
                "description": "Realistic security impact.",
            },
            "attack_context": {
                "type": "string",
                "description": "How attacker-controlled input could potentially exploit the issue.",
            },
            "remediation": {
                "type": "string",
                "description": "Specific secure remediation for this code.",
            },
            "patch_strategy": {
                "type": "string",
                "description": "Minimal behavior-preserving strategy for fixing the code.",
            },
            "confidence": {
                "type": "string",
                "enum": ["HIGH", "MEDIUM", "LOW"],
            },
        },
        "required": [
            "title",
            "root_cause",
            "impact",
            "attack_context",
            "remediation",
            "patch_strategy",
            "confidence",
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
            f"Gemini analysis failed: {exc}"
        ) from exc

    return {
        "vulnerability_id": vulnerability.get("id"),
        "rule_id": vulnerability.get("rule_id"),
        "file": file_path,
        "line": line,

        "severity": vulnerability.get("severity"),
        "risk": vulnerability.get("risk"),
        "risk_score": vulnerability.get("risk_score"),

        "title": result["title"],
        "root_cause": result["root_cause"],
        "impact": result["impact"],
        "attack_context": result["attack_context"],
        "remediation": result["remediation"],
        "patch_strategy": result["patch_strategy"],
        "confidence": result["confidence"],

        "cwe": cwe,
        "owasp": owasp,

        "code_context": code_context,
        "status": "ai_analyzed",
        "model": GEMINI_MODEL,
    }