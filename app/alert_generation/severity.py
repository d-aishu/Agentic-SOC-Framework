"""Initial project-defined severity classification (see config/severity_rules.py)."""
from __future__ import annotations

from app.config import severity_rules as rules
from app.schemas.alert import Severity


def compute_severity(category: str, total_bytes: float = 0, repeated_connections: float = 0) -> tuple[Severity, str]:
    """Return (severity, human-readable rationale)."""
    base = rules.BASE_SEVERITY.get(category, rules.DEFAULT_ATTACK_SEVERITY)
    reasons = [f"base={base} (category '{category}')"]
    level = rules.SEVERITY_ORDER.index(base)

    if category != "Normal":
        if total_bytes >= rules.HIGH_VOLUME_BYTES_THRESHOLD:
            level += 1
            reasons.append(f"+1 high-volume flow (>= {rules.HIGH_VOLUME_BYTES_THRESHOLD} bytes)")
        if repeated_connections >= rules.REPEATED_CONNECTIONS_THRESHOLD:
            level += 1
            reasons.append(f"+1 repeated connections (>= {rules.REPEATED_CONNECTIONS_THRESHOLD} recent flows between the pair)")

    capped = min(level, len(rules.SEVERITY_ORDER) - 1)
    if capped != level:
        reasons.append("capped at critical")
    return Severity(rules.SEVERITY_ORDER[capped]), "; ".join(reasons)
