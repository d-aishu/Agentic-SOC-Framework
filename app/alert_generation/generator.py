"""Convert cleaned dataset records into structured alerts (+ separate ground truth)."""
from __future__ import annotations

import logging
import math

import pandas as pd

from app.alert_generation.descriptions import build_description, build_evidence_summary
from app.alert_generation.severity import compute_severity
from app.dataset.columns import ATTACK_CATEGORIES, CATEGORY_ALIASES, UNKNOWN_CATEGORY
from app.schemas.alert import Alert, AlertSource, GenerateAlertsRequest, GroundTruth
from app.utils.exceptions import InvalidRequestError

logger = logging.getLogger(__name__)

# Observable flow features copied into ``evidence`` (only those present in the data).
EVIDENCE_FEATURES = [
    "state", "service", "dur", "sbytes", "dbytes", "spkts", "dpkts", "sttl", "dttl",
    "sload", "dload", "sloss", "dloss", "tcprtt", "ct_state_ttl", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_dst_src_ltm", "is_sm_ips_ports",
]


def _py(value):
    """numpy/pandas scalar -> plain JSON-friendly Python value (missing -> None)."""
    if value is None or value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if hasattr(value, "item"):
        value = value.item()
    return round(value, 6) if isinstance(value, float) else value


def _balanced_sample(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    """Take ~n rows spreading the quota evenly over categories (rare classes are fully used first)."""
    groups = {str(c): g for c, g in df.groupby("attack_cat", observed=True)}
    quota = {c: 0 for c in groups}
    active, remaining = list(groups), n
    while remaining > 0 and active:
        share = max(remaining // len(active), 1)
        for c in list(active):
            take = min(share, len(groups[c]) - quota[c], remaining)
            quota[c] += take
            remaining -= take
            if quota[c] >= len(groups[c]):
                active.remove(c)
            if remaining == 0:
                break
    parts = [g.sample(n=quota[c], random_state=seed) for c, g in groups.items() if quota[c] > 0]
    return pd.concat(parts)


def _canonical_categories(names: list[str]) -> set[str]:
    result = set()
    for n in names:
        canon = CATEGORY_ALIASES.get(n.strip().lower())
        if canon is None and n.strip().lower() == UNKNOWN_CATEGORY.lower():
            canon = UNKNOWN_CATEGORY
        if canon is None or canon == "Normal":
            raise InvalidRequestError(
                f"Unknown attack category '{n}'. Valid values: {ATTACK_CATEGORIES + [UNKNOWN_CATEGORY]}"
            )
        result.add(canon)
    return result


class AlertGenerator:
    def __init__(self, source: AlertSource = AlertSource.DATASET):
        self.source = source

    def select_records(self, df: pd.DataFrame, req: GenerateAlertsRequest) -> pd.DataFrame:
        attacks = df[df["label"] == 1]
        if req.categories:
            attacks = attacks[attacks["attack_cat"].isin(_canonical_categories(req.categories))]
        benign = df[df["label"] == 0]

        n_benign = round(req.max_alerts * req.benign_fraction) if len(attacks) else 0
        n_attack = req.max_alerts - n_benign
        if len(attacks) == 0:
            raise InvalidRequestError("No attack records match the request (check 'categories').")

        n_attack = min(n_attack, len(attacks))
        picked = (_balanced_sample(attacks, n_attack, req.seed) if req.strategy == "balanced"
                  else attacks.sample(n=n_attack, random_state=req.seed))
        n_benign = min(n_benign, len(benign))
        if n_benign:
            picked = pd.concat([picked, benign.sample(n=n_benign, random_state=req.seed)])
        return picked.sort_values(["timestamp", "source_file", "source_row"], na_position="last")

    def generate(self, df: pd.DataFrame, req: GenerateAlertsRequest, start_index: int = 1
                 ) -> tuple[list[Alert], list[GroundTruth]]:
        selected = self.select_records(df, req)
        evidence_cols = [c for c in EVIDENCE_FEATURES if c in selected.columns]
        alerts, truths = [], []

        for i, row in enumerate(selected.to_dict("records"), start=start_index):
            alert_id = f"ALR-{i:06d}"
            category = str(row["attack_cat"])
            protocol = _py(row.get("proto"))
            protocol = None if protocol in (None, "unknown") else str(protocol).upper()
            src, dst = _py(row.get("srcip")), _py(row.get("dstip"))
            sport, dport = _py(row.get("sport")), _py(row.get("dsport"))
            ts = row.get("timestamp")
            ts = None if ts is None or pd.isna(ts) else ts.to_pydatetime()
            evidence = {c: _py(row[c]) for c in evidence_cols}

            severity, rationale = compute_severity(
                category,
                total_bytes=(evidence.get("sbytes") or 0) + (evidence.get("dbytes") or 0),
                repeated_connections=evidence.get("ct_dst_src_ltm") or 0,
            )
            summary = build_evidence_summary(protocol, src, sport, dst, dport, evidence)
            record_ref = f"{row['source_file']}#row {row['source_row']}"

            alerts.append(Alert(
                alert_id=alert_id, timestamp=ts, source=self.source,
                source_ip=src, destination_ip=dst, protocol=protocol,
                source_port=sport, destination_port=dport,
                attack_category=category, severity=severity, severity_rationale=rationale,
                description=build_description(category, summary),
                detection_method="dataset_label",
                evidence_summary=summary, evidence=evidence, record_ref=record_ref,
            ))
            truths.append(GroundTruth(
                alert_id=alert_id, label=int(row["label"]), attack_category=category,
                original_category_value=_py(row.get("attack_cat_raw")), record_ref=record_ref,
            ))
        logger.info("Generated %d alerts (%s sampling)", len(alerts), req.strategy)
        return alerts, truths
