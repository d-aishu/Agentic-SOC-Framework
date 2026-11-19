from __future__ import annotations
import json, os, re
from pathlib import Path
from typing import Any
from app.agents.common import result

def _indicators(alert: dict[str, Any]) -> list[str]:
    text = str(alert)
    found = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    found.update(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
    found.update(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))
    return sorted(found)

def threat_intel_node(state: dict[str, Any]) -> dict[str, Any]:
    alert = state["alert"]
    indicators = _indicators(alert)
    feed_path = Path(os.getenv("SOC_THREAT_FEED", "knowledge/threat_intelligence/indicators.json"))
    feed = {}
    try:
        if feed_path.exists(): feed = json.loads(feed_path.read_text(encoding="utf-8"))
    except Exception:
        feed = {}
    matches, unknown = [], []
    for indicator in indicators:
        entry = feed.get(indicator)
        if entry and str(entry.get("verdict", "unknown")).lower() in {"malicious", "confirmed_malicious"}:
            matches.append({"indicator": indicator, "verdict": "confirmed_malicious", "source": entry.get("source", "local configured feed"), "reference": entry.get("reference", "")})
        else:
            unknown.append(indicator)
    rag_docs = []
    rag = state.get("rag_engine")
    if rag:
        try: rag_docs = rag.retrieve("Threat intelligence and MITRE ATT&CK guidance for " + ", ".join(indicators), k=4)
        except Exception: rag_docs = []
    findings = [f"Found {len(indicators)} observable indicator(s)."]
    findings.append(f"{len(matches)} indicator(s) matched confirmed malicious entries in the configured local feed.")
    if unknown: findings.append(f"{len(unknown)} indicator(s) remain unknown; unknown is not classified as malicious.")
    sources = [{"source": m["source"], "reference": m["reference"]} for m in matches]
    sources += [{"source": d["source"], "reference": d["title"]} for d in rag_docs]
    state.setdefault("agent_results", {})["threat_intel"] = result("Threat Intelligence Agent", findings,
        [f"confirmed malicious: {m['indicator']}" for m in matches] + [f"unknown: {x}" for x in unknown],
        0.9 if matches else (0.45 if indicators else 0.2), sources=sources,
        details={"indicators": indicators, "confirmed_malicious": matches, "unknown": unknown, "knowledge_retrieval": rag_docs})
    return state
