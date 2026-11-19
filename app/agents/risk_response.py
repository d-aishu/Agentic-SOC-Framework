from __future__ import annotations
from typing import Any
from app.agents.common import result

def risk_response_node(state: dict[str, Any]) -> dict[str, Any]:
    alert = state["alert"]
    results = state.get("agent_results", {})
    sev = str(state.get("routing_context", {}).get("severity", "low")).lower()
    base = {"informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 75}.get(sev, 15)
    investigation = results.get("investigation", {})
    conf = float(investigation.get("confidence", 0.3))
    evidence_n = len(investigation.get("evidence", []))
    ti = results.get("threat_intel", {}).get("details", {})
    malicious_n = len(ti.get("confirmed_malicious", []))
    related_n = len(results.get("correlation", {}).get("details", {}).get("related_alerts", []))
    impact = int(state.get("routing_decision", {}).get("impact_score", 0))
    score = min(100, int(base + conf * 10 + min(evidence_n, 8) * 2 + min(malicious_n, 3) * 12 + min(related_n, 5) * 3 + impact * 0.5))
    level = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
    actions = [{"action": "preserve_alert_evidence", "mode": "simulated", "requires_human_approval": False,
                "reason": "Preserving evidence supports later review and does not disrupt production systems."},
               {"action": "monitor_observed_indicators", "mode": "simulated", "requires_human_approval": False,
                "reason": "Monitoring allows analysts to look for repeated activity."}]
    if level in ("high", "critical"):
        actions.append({"action": "isolate_affected_host_or_block_indicator", "mode": "recommendation_only",
                        "requires_human_approval": True,
                        "reason": "This action may disrupt legitimate activity and must be approved by a human analyst.",
                        "executed": False})
    state["risk_score"] = score
    state["risk_level"] = level
    state["recommended_actions"] = actions
    state["agent_results"]["risk_response"] = result("Risk & Response Agent",
        [f"Calculated risk score: {score}/100 ({level}).", "Response actions are recommendations/simulations only; no real system changes were made."],
        [f"severity contribution: {base}", f"investigation confidence: {conf:.2f}", f"confirmed malicious indicators: {malicious_n}", f"candidate correlated alerts: {related_n}", f"potential impact contribution: {impact}"],
        min(0.95, max(0.4, conf + 0.2)), details={"risk_score": score, "risk_level": level, "potential_impact_score": impact, "actions": actions})
    return state
