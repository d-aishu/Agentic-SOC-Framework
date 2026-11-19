"""Initial, PROJECT-DEFINED severity rules.

These are NOT an industry standard and NOT learned from data. They are a
transparent starting point (category -> base level, plus two simple
escalation rules) and are meant to be tuned in later phases.
"""
from __future__ import annotations

# Ordered from least to most severe.
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

# Base level per (canonical) UNSW-NB15 attack category.
BASE_SEVERITY: dict[str, str] = {
    "Normal": "informational",
    "Reconnaissance": "low",
    "Analysis": "low",
    "Fuzzers": "medium",
    "Generic": "medium",
    "DoS": "high",
    "Exploits": "high",
    "Backdoor": "critical",
    "Shellcode": "critical",
    "Worms": "critical",
}
DEFAULT_ATTACK_SEVERITY = "medium"  # used for "Unknown" / unmapped attack categories

# Escalation rules: each one raises severity by one level (capped at critical).
# They are never applied to benign ("Normal") records.
HIGH_VOLUME_BYTES_THRESHOLD = 1_000_000   # sbytes + dbytes in one flow
REPEATED_CONNECTIONS_THRESHOLD = 30       # ct_dst_src_ltm: recent flows between same src/dst pair
