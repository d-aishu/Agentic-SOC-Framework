"""Alert schemas.

Three distinct objects keep ground truth away from the AI agents:

* ``Alert``          - the full SOC-platform record (includes the reported category/severity).
* ``AgentAlertView`` - what downstream agents may see: observable evidence ONLY.
* ``GroundTruth``    - the dataset labels, exposed only via the evaluation endpoint.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    DATASET = "dataset"
    WAZUH = "wazuh"   # reserved for a later phase


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    alert_id: str
    timestamp: Optional[datetime] = None
    source: AlertSource
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    attack_category: str = Field(description="Category reported with the alert (dataset annotation in dataset mode).")
    severity: Severity
    severity_rationale: str = Field(description="Which project-defined rules produced the severity.")
    description: str
    detection_method: str = Field(
        description="How the alert was produced. 'dataset_label' = taken from dataset annotation; "
                    "NO ML/AI detection is performed in Phase 1."
    )
    evidence_summary: str = Field(description="Neutral text built only from observable flow evidence.")
    evidence: dict[str, Any] = Field(description="Observable flow features (no labels).")
    record_ref: str = Field(description="Origin of the alert, e.g. 'UNSW-NB15_1.csv#row 123'.")

    def to_agent_view(self) -> "AgentAlertView":
        return AgentAlertView(
            alert_id=self.alert_id,
            timestamp=self.timestamp,
            source=self.source,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            protocol=self.protocol,
            source_port=self.source_port,
            destination_port=self.destination_port,
            evidence_summary=self.evidence_summary,
            evidence=self.evidence,
        )


class AgentAlertView(BaseModel):
    """Leak-free view: no category, no severity, no label, no record_ref."""
    alert_id: str
    timestamp: Optional[datetime] = None
    source: AlertSource
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    evidence_summary: str
    evidence: dict[str, Any]


class GroundTruth(BaseModel):
    alert_id: str
    label: int = Field(description="Original binary label: 0 = normal, 1 = attack.")
    attack_category: str = Field(description="Cleaned canonical category.")
    original_category_value: Optional[str] = Field(None, description="Category string exactly as in the CSV.")
    record_ref: str


class AlertListResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: list[Alert]


class GenerateAlertsRequest(BaseModel):
    max_alerts: int = Field(1000, ge=1, le=100_000, description="Total alerts to generate.")
    categories: Optional[list[str]] = Field(None, description="Only these attack categories (default: all).")
    benign_fraction: float = Field(0.0, ge=0.0, le=0.9, description="Share of alerts that are benign flows (to test false positives).")
    strategy: str = Field("balanced", pattern="^(random|balanced)$",
                          description="'balanced' = similar count per category; 'random' = natural class imbalance.")
    seed: int = Field(42, description="Random seed (reproducible sampling).")
    replace_existing: bool = Field(True, description="Replace previous alerts (True) or append (False).")


class GenerateAlertsResponse(BaseModel):
    generated: int
    total_alerts_now: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    benign_included: int
    message: str


class AlertStats(BaseModel):
    total: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    by_protocol: dict[str, int]
    severity_by_category: dict[str, dict[str, int]]
    with_ip_addresses: int
    time_range: Optional[dict[str, datetime]] = None
