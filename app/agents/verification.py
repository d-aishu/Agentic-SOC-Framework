from __future__ import annotations
from typing import Any
from app.agents.common import result

def verification_node(state: dict[str, Any]) -> dict[str, Any]:
    events = state.get("verification_events", [])
    suspicious = [e for e in events if e.get("suspicious") is True or str(e.get("status", "")).lower() in {"suspicious", "malicious", "continued"}]
    executed = bool(state.get("response_execution_confirmed", False))
    if suspicious:
        status = "unresolved"
        findings = [f"{len(suspicious)} subsequent event(s) were marked suspicious in the supplied verification data.", "Further investigation is required."]
    elif events and executed:
        status = "resolved"
        findings = ["No suspicious activity was found in the supplied verification events.", "The response execution was explicitly marked as confirmed."]
    elif events:
        status = "requires_further_investigation"
        findings = ["No suspicious event was present in the supplied sample, but response execution was not confirmed.", "The incident is not declared resolved."]
    else:
        status = "requires_further_investigation"
        findings = ["No subsequent or simulated verification events were supplied.", "The system cannot claim that the attack was stopped."]
    state["verification"] = {"status": status, "suspicious_events": suspicious,
                              "response_execution_confirmed": executed}
    state["agent_results"]["verification"] = result("Verification Agent", findings,
        [str(e) for e in suspicious], 0.9 if events else 0.2,
        details=state["verification"])
    if status != "resolved": state["reinvestigation_count"] = int(state.get("reinvestigation_count", 0)) + 1
    return state
