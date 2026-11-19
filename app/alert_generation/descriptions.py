"""Text generation for alerts.

``evidence_summary`` uses ONLY observable flow data (safe for agents).
``description`` additionally names the reported category (not shown to agents).
"""
from __future__ import annotations

from typing import Any

CATEGORY_BLURBS = {
    "Analysis": "Probing/analysis activity (e.g. port scans, spam, web-file probing)",
    "Backdoor": "Possible backdoor communication bypassing normal authentication",
    "DoS": "Possible denial-of-service traffic",
    "Exploits": "Possible exploitation of a known vulnerability",
    "Fuzzers": "Possible fuzzing (malformed/random input aimed at crashing or probing a service)",
    "Generic": "Generic attack technique (e.g. cryptographic collision attempts)",
    "Reconnaissance": "Reconnaissance activity gathering information about targets",
    "Shellcode": "Possible shellcode delivery (small code used to take control of a host)",
    "Worms": "Possible self-replicating worm activity",
    "Normal": "Benign flow (included to test false-positive handling)",
    "Unknown": "Attack-labelled flow with no usable category",
}


def _fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def build_evidence_summary(protocol: str | None, src: str | None, sport: int | None,
                           dst: str | None, dport: int | None, ev: dict[str, Any]) -> str:
    def endpoint(ip, port):
        if ip is None and port is None:
            return "unknown endpoint"
        return f"{ip or 'unknown-ip'}" + (f":{port}" if port is not None else "")

    parts = [f"{protocol or 'Unknown-protocol'} flow {endpoint(src, sport)} -> {endpoint(dst, dport)}"]
    if ev.get("service") not in (None, "unknown"):
        parts.append(f"service {ev['service']}")
    if ev.get("state") not in (None, "unknown"):
        parts.append(f"state {ev['state']}")
    sb, db = ev.get("sbytes"), ev.get("dbytes")
    if sb is not None and db is not None:
        parts.append(f"{_fmt_bytes(sb)} sent / {_fmt_bytes(db)} received")
    sp, dp = ev.get("spkts"), ev.get("dpkts")
    if sp is not None and dp is not None:
        parts.append(f"{int(sp)}/{int(dp)} packets")
    if ev.get("dur") is not None:
        parts.append(f"duration {float(ev['dur']):.3f}s")
    return ", ".join(parts) + "."


def build_description(category: str, evidence_summary: str) -> str:
    return f"{CATEGORY_BLURBS.get(category, category)}. {evidence_summary}"
