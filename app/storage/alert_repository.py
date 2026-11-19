"""In-memory alert repository with JSON-lines persistence.

Alerts and ground truth are stored in SEPARATE files/dicts. The interface is small so a
PostgreSQL implementation can replace it later.
"""
from __future__ import annotations

import logging
import threading
from collections import Counter
from pathlib import Path
from typing import Optional

from app.schemas.alert import Alert, AlertStats, GroundTruth

logger = logging.getLogger(__name__)


class AlertRepository:
    def __init__(self, directory: Path):
        self._alerts_file = directory / "alerts.jsonl"
        self._truth_file = directory / "ground_truth.jsonl"
        self._lock = threading.Lock()
        self._alerts: dict[str, Alert] = {}
        self._truth: dict[str, GroundTruth] = {}

    # ---- writes ---------------------------------------------------------------
    def replace_all(self, alerts: list[Alert], truths: list[GroundTruth]) -> None:
        with self._lock:
            self._alerts = {a.alert_id: a for a in alerts}
            self._truth = {t.alert_id: t for t in truths}
        self.save()

    def add_many(self, alerts: list[Alert], truths: list[GroundTruth]) -> None:
        with self._lock:
            self._alerts.update({a.alert_id: a for a in alerts})
            self._truth.update({t.alert_id: t for t in truths})
        self.save()

    def clear(self) -> int:
        with self._lock:
            n = len(self._alerts)
            self._alerts, self._truth = {}, {}
        self.save()
        return n

    # ---- reads ------------------------------------------------------------------
    def count(self) -> int:
        return len(self._alerts)

    def next_index(self) -> int:
        with self._lock:
            return max((int(a.split("-")[1]) for a in self._alerts), default=0) + 1

    def get(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def get_truth(self, alert_id: str) -> Optional[GroundTruth]:
        return self._truth.get(alert_id)

    def _filtered(self, category: Optional[str], severity: Optional[str], source: Optional[str]) -> list[Alert]:
        items = list(self._alerts.values())
        if category:
            items = [a for a in items if a.attack_category.lower() == category.strip().lower()]
        if severity:
            items = [a for a in items if a.severity.value == severity]
        if source:
            items = [a for a in items if a.source.value == source]
        return items

    def query(self, category=None, severity=None, source=None, skip: int = 0, limit: int = 50) -> tuple[int, list[Alert]]:
        with self._lock:
            items = self._filtered(category, severity, source)
        return len(items), items[skip: skip + limit]

    def stats(self) -> AlertStats:
        with self._lock:
            alerts = list(self._alerts.values())
        matrix: dict[str, Counter] = {}
        for a in alerts:
            matrix.setdefault(a.attack_category, Counter())[a.severity.value] += 1
        stamps = [a.timestamp for a in alerts if a.timestamp]
        return AlertStats(
            total=len(alerts),
            by_category=dict(Counter(a.attack_category for a in alerts)),
            by_severity=dict(Counter(a.severity.value for a in alerts)),
            by_source=dict(Counter(a.source.value for a in alerts)),
            by_protocol=dict(Counter((a.protocol or "unknown") for a in alerts).most_common(10)),
            severity_by_category={k: dict(v) for k, v in matrix.items()},
            with_ip_addresses=sum(1 for a in alerts if a.source_ip and a.destination_ip),
            time_range={"first": min(stamps), "last": max(stamps)} if stamps else None,
        )

    # ---- persistence ----------------------------------------------------------------
    def save(self) -> None:
        try:
            with self._lock:
                self._alerts_file.write_text(
                    "".join(a.model_dump_json() + "\n" for a in self._alerts.values()), encoding="utf-8")
                self._truth_file.write_text(
                    "".join(t.model_dump_json() + "\n" for t in self._truth.values()), encoding="utf-8")
        except Exception:
            logger.exception("Could not persist alerts")

    def load(self) -> int:
        try:
            if self._alerts_file.exists():
                alerts = [Alert.model_validate_json(l) for l in self._alerts_file.read_text(encoding="utf-8").splitlines() if l.strip()]
                truths = []
                if self._truth_file.exists():
                    truths = [GroundTruth.model_validate_json(l) for l in self._truth_file.read_text(encoding="utf-8").splitlines() if l.strip()]
                with self._lock:
                    self._alerts = {a.alert_id: a for a in alerts}
                    self._truth = {t.alert_id: t for t in truths}
                logger.info("Restored %d alerts from disk", len(alerts))
        except Exception:
            logger.exception("Stored alerts are unreadable; starting empty")
        return self.count()
