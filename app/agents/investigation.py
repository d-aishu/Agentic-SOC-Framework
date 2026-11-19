from __future__ import annotations
from typing import Any
from app.agents.common import get_llm, invoke_json, result

def investigation_node(state: dict[str, Any]) -> dict[str, Any]:
    alert = state["alert"]
    evidence = alert.get("evidence") or {}
    summary = alert.get("evidence_summary") or "No evidence summary supplied."
    findings = ["Alert evidence reviewed.", summary]
    suspicious_terms = ["scan", "failed", "unusual", "suspicious", "high rate", "repeated", "payload"]
    text = (summary + " " + str(evidence)).lower()
    if any(t in text for t in suspicious_terms): findings.append("Observable fields contain patterns that warrant security review.")
    confidence = 0.55 if evidence else 0.25
    llm_data = invoke_json(get_llm(),
        "You are a cautious SOC investigation analyst. Use ONLY the observable alert data. Do not infer dataset labels. Return JSON with findings (array), suspected_attack_type (string or unknown), confidence (0..1), recommended_next_investigation (array), evidence (array).",
        {"alert": alert})
    details = {"suspected_attack_type": "unknown", "recommended_next_investigation": [], "llm_assisted": False}
    if llm_data:
        findings = [str(x) for x in llm_data.get("findings", findings)]
        details.update({"suspected_attack_type": str(llm_data.get("suspected_attack_type", "unknown")),
                        "recommended_next_investigation": llm_data.get("recommended_next_investigation", []), "llm_assisted": True})
        confidence = float(llm_data.get("confidence", confidence))
    else:
        details["recommended_next_investigation"] = ["Check indicator reputation if IP/domain/hash values are present", "Compare with nearby alerts"]
    state.setdefault("agent_results", {})["investigation"] = result("Investigation Agent", findings,
        [f"evidence_summary: {summary}"] + [f"{k}={v}" for k,v in list(evidence.items())[:12]], confidence, details=details)
    return state
