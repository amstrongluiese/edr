from .config import RISK_WEIGHTS


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def risk_level(score: int) -> str:
    return final_classification(score)


def final_classification(score: int) -> str:
    score = clamp_score(score)
    if score == 0:
        return "SAFE"
    if score <= 10:
        return "INFORMATIONAL"
    if score <= 30:
        return "LOW RISK"
    if score <= 60:
        return "SUSPICIOUS"
    if score <= 85:
        return "HIGH RISK"
    return "CONFIRMED THREAT"


def evidence_classification(
    alert_type: str,
    evidence_types: list[str],
    *,
    has_ioc: bool = False,
    has_cve: bool = False,
    validation_confirmed: bool = False,
) -> str:
    unique = {item for item in evidence_types if item}
    if validation_confirmed or alert_type in {"malicious_ip", "malicious_domain", "malicious_url", "malicious_hash"}:
        return "CONFIRMED THREAT"
    if has_ioc:
        return "CONFIRMED THREAT"
    if has_cve:
        return "HIGH RISK"
    detection_types = unique & {
        "sigma_rule", "yara_rule", "beaconing", "port_scan", "successful_login_after_failures",
        "failed_attempts", "suspicious_process", "suspicious_dns", "repeated_connections",
        "traffic_spike", "startup_persistence", "suspicious_file_path", "unsigned_executable",
        "database_access_attempt", "risky_open_port",
    }
    strong = detection_types & {"sigma_rule", "yara_rule", "beaconing", "port_scan", "successful_login_after_failures"}
    if len(strong) >= 2 or len(detection_types) >= 3:
        return "HIGH RISK"
    if len(unique - {"unknown_device", "new_device", "possible_doh", "safe_baseline"}) >= 2:
        return "SUSPICIOUS"
    if alert_type in {"unknown_device", "new_device"}:
        return "INFORMATIONAL"
    return "LOW RISK"


def confidence_label(score: int) -> str:
    score = clamp_score(score)
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 85:
        return "High"
    return "Confirmed"


def weighted_score(alert_types: list[str]) -> int:
    return clamp_score(sum(RISK_WEIGHTS.get(item, 0) for item in alert_types))

