from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
from app.agents.common import result

def _parse_time(value):
    if not value: return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception: return None

def correlation_node(state: dict[str, Any]) -> dict[str, Any]:
    current = state["alert"]
    candidates = state.get("existing_alerts", [])
    related, reasons = [], []
    current_time = _parse_time(current.get("timestamp"))
    for item in candidates:
        if item.get("alert_id") == current.get("alert_id"): continue
        matched = []
        for field in ("source_ip", "destination_ip"):
            if current.get(field) and current.get(field) == item.get(field): matched.append(f"same {field}")
        if current.get("protocol") and current.get("protocol") == item.get("protocol"): matched.append("same protocol")
        if current.get("reported_category") and current.get("reported_category") == item.get("reported_category"):
            matched.append("same reported attack category")
        other_time = _parse_time(item.get("timestamp"))
        if current_time and other_time:
            delta = abs((current_time - other_time).total_seconds())
            if delta <= 3600: matched.append(f"timestamps within {int(delta)} seconds")
        if matched and any("same source_ip" in x or "same destination_ip" in x for x in matched):
            related.append({"alert_id": item.get("alert_id"), "matched_features": matched,
                            "source_ip": item.get("source_ip"), "destination_ip": item.get("destination_ip"),
                            "timestamp": item.get("timestamp"), "protocol": item.get("protocol")})
    if related:
        reasons.append(f"Found {len(related)} alert(s) sharing at least one endpoint IP with this alert.")
        reasons.append("These are candidate correlations, not proof of a common attacker or causal sequence.")
    else: reasons.append("No related alerts were identified using the available endpoint, protocol and time evidence.")
    state.setdefault("agent_results", {})["correlation"] = result("Alert Correlation Agent", reasons,
        [f"related alert: {x['alert_id']} ({'; '.join(x['matched_features'])})" for x in related],
        0.75 if related else 0.55, details={"related_alerts": related, "candidate_count": len(related)})
    return state
