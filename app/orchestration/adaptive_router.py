from __future__ import annotations
from typing import Any
import json
from pathlib import Path

DEFAULT_RULES = {
    "medium_score": 35,
    "high_score": 65,
    "low_evidence_threshold": 2,
    "always_run_investigation": True,
    "high_impact_categories": ["ransomware", "exploits", "backdoors"],
    "high_bytes_threshold": 1_000_000,
    "medium_bytes_threshold": 100_000,
    "high_repeat_threshold": 10,
    "medium_repeat_threshold": 5,
    "low_confidence_threshold": 0.45,
}

def load_routing_rules(path: str | Path | None = None) -> dict[str, Any]:
    """Load optional JSON routing overrides; built-in defaults remain the fallback."""
    config_path = Path(path) if path else Path(__file__).resolve().parents[1] / "config" / "routing_rules.json"
    try:
        if config_path.exists():
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict): return {**DEFAULT_RULES, **loaded}
    except (OSError, json.JSONDecodeError):
        pass
    return dict(DEFAULT_RULES)

def _impact_score(alert: dict[str, Any]) -> int:
    evidence = alert.get("evidence") or {}
    score = 0
    text = str(evidence).lower() + " " + str(alert.get("evidence_summary", "")).lower()
    if any(word in text for word in ("admin", "root", "critical", "sensitive")): score += 20
    if alert.get("destination_port") in (22, 23, 3389, 445, 1433, 3306): score += 10
    if evidence.get("dbytes", 0) and float(evidence.get("dbytes", 0) or 0) > 1_000_000: score += 10
    return min(score, 30)

def evidence_based_severity(alert: dict[str, Any], rules: dict[str, Any] | None = None) -> str:
    """For dataset alerts, derive routing severity from observable features, not dataset labels."""
    cfg = {**DEFAULT_RULES, **(rules or {})}
    if alert.get("source") != "dataset":
        return str(alert.get("severity", "low")).lower()
    evidence = alert.get("evidence") or {}
    total_bytes = float(evidence.get("sbytes") or 0) + float(evidence.get("dbytes") or 0)
    repeats = float(evidence.get("ct_dst_src_ltm") or 0)
    if total_bytes >= cfg["high_bytes_threshold"] or repeats >= cfg["high_repeat_threshold"]:
        return "high"
    if total_bytes >= cfg["medium_bytes_threshold"] or repeats >= cfg["medium_repeat_threshold"]:
        return "medium"
    return "low"

def _related_candidate_count(alert: dict[str, Any], candidates: list[dict[str, Any]]) -> int:
    endpoints = {alert.get("source_ip"), alert.get("destination_ip")} - {None, ""}
    if not endpoints: return 0
    count = 0
    for item in candidates:
        other = {item.get("source_ip"), item.get("destination_ip")} - {None, ""}
        if endpoints & other: count += 1
    return count

def choose_route(alert: dict[str, Any], existing_alerts: list[dict[str, Any]] | None = None,
                 rules: dict[str, Any] | None = None) -> dict[str, Any]:
    """Choose optional specialist agents. Alert category is not used as a truth label."""
    cfg = {**DEFAULT_RULES, **(rules or {})}
    evidence = alert.get("evidence") or {}
    evidence_count = sum(v is not None for v in evidence.values())
    severity = str((alert.get("routing_severity") or alert.get("severity") or "low")).lower()
    severity_points = {"informational": 0, "low": 10, "medium": 25, "high": 40, "critical": 50}.get(severity, 10)
    impact = _impact_score(alert)
    category = str(alert.get("routing_category", "")).lower()
    if category and category in {str(x).lower() for x in cfg["high_impact_categories"]}: impact = min(30, impact + 15)
    related_count = _related_candidate_count(alert, existing_alerts or [])
    correlation_signal = min(15, related_count * 3)
    uncertainty = 15 if evidence_count < cfg["low_evidence_threshold"] else 0
    score = min(100, severity_points + impact + correlation_signal + uncertainty)
    if severity in ("high", "critical") or score >= cfg["high_score"]:
        depth = "deep"; selected = ["investigation", "threat_intel", "correlation"]
    elif severity == "medium" or score >= cfg["medium_score"]:
        depth = "standard"; selected = ["investigation", "threat_intel", "correlation"]
    else:
        depth = "basic"; selected = ["investigation"]
    return {"depth": depth, "risk_hint": score, "selected_agents": selected,
            "impact_score": impact,
            "reasons": [f"severity={severity}", f"observable_evidence_fields={evidence_count}",
                        f"related_alert_candidates={related_count}", f"potential_impact_points={impact}"]}
