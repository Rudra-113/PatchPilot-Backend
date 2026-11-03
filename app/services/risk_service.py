from typing import Any


SEVERITY_SCORE = {
    "ERROR": 3,
    "WARNING": 2,
    "INFO": 1,
}

IMPACT_SCORE = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

LIKELIHOOD_SCORE = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

CONFIDENCE_SCORE = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def calculate_risk(
    severity: str,
    impact: str,
    likelihood: str,
    confidence: str,
) -> dict[str, Any]:

    severity_score = SEVERITY_SCORE.get(severity.upper(), 1)
    impact_score = IMPACT_SCORE.get(impact.upper(), 1)
    likelihood_score = LIKELIHOOD_SCORE.get(
        likelihood.upper(), 1
    )
    confidence_score = CONFIDENCE_SCORE.get(
        confidence.upper(), 1
    )

    score = (
        severity_score
        + impact_score
        + likelihood_score
        + confidence_score
    )

    if score >= 10:
        risk = "CRITICAL"
    elif score >= 8:
        risk = "HIGH"
    elif score >= 5:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "risk_score": score,
        "severity_score": severity_score,
        "impact_score": impact_score,
        "likelihood_score": likelihood_score,
        "confidence_score": confidence_score,
    }