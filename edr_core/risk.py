from .config import RISK_WEIGHTS


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def risk_level(score: int) -> str:
    score = clamp_score(score)
    if score <= 10:
        return "Informational"
    if score <= 30:
        return "Low Risk"
    if score <= 60:
        return "Suspicious"
    if score <= 80:
        return "High Risk"
    return "Critical"


def weighted_score(alert_types: list[str]) -> int:
    return clamp_score(sum(RISK_WEIGHTS.get(item, 0) for item in alert_types))

