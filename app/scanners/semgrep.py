import json
import subprocess
from pathlib import Path

from app.services.risk_service import calculate_risk


class SemgrepScanner:
    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def scan(self, target_path: str) -> dict:
        target = Path(target_path).resolve()

        if not target.exists() or not target.is_dir():
            raise ValueError(
                "Scan target does not exist or is not a directory."
            )

        command = [
            "semgrep",
            "--config",
            "auto",
            "--json",
            "--no-git-ignore",
            str(target),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

        except subprocess.TimeoutExpired:
            raise RuntimeError("Semgrep scan timed out.")

        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep was not found. Make sure it is installed "
                "and available in PATH."
            )

        if not result.stdout.strip():
            raise RuntimeError(
                f"Semgrep returned no output. Error: {result.stderr}"
            )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(
                f"Could not parse Semgrep JSON output: "
                f"{result.stdout[:1000]}"
            )

        return self._normalize_results(data)

    def _normalize_results(self, data: dict) -> dict:
        vulnerabilities = []

        for finding in data.get("results", []):
            extra = finding.get("extra", {})
            metadata = extra.get("metadata", {})

            impact = str(
                metadata.get("impact", "MEDIUM")
            ).upper()

            likelihood = str(
                metadata.get("likelihood", "MEDIUM")
            ).upper()

            confidence = str(
                metadata.get("confidence", "MEDIUM")
            ).upper()

            severity = str(
                extra.get("severity", "WARNING")
            ).upper()

            risk = calculate_risk(
                severity=severity,
                impact=impact,
                likelihood=likelihood,
                confidence=confidence,
            )

            vulnerabilities.append(
                {
                    "id": f"SEM-{len(vulnerabilities) + 1:04d}",
                    "rule_id": finding.get("check_id"),
                    "severity": severity,
                    "message": extra.get("message", ""),
                    "file": finding.get("path"),
                    "line": finding.get("start", {}).get("line"),
                    "column": finding.get("start", {}).get("col"),
                    "end_line": finding.get("end", {}).get("line"),
                    "language": finding.get("language"),

                    "impact": impact,
                    "likelihood": likelihood,
                    "confidence": confidence,

                    "risk": risk["risk"],
                    "risk_score": risk["risk_score"],

                    "severity_score": risk["severity_score"],
                    "impact_score": risk["impact_score"],
                    "likelihood_score": risk["likelihood_score"],
                    "confidence_score": risk["confidence_score"],

                    "metadata": metadata,
                    "scanner": "semgrep",
                }
            )

        return {
            "scanner": "semgrep",
            "total": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }