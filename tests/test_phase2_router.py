from app.orchestration.adaptive_router import choose_route

def test_low_alert_uses_basic_route():
    d = choose_route({"severity": "low", "evidence": {"proto": "tcp"}}, [])
    assert d["depth"] == "basic"
    assert d["selected_agents"] == ["investigation"]

def test_medium_alert_uses_specialists():
    d = choose_route({"severity": "medium", "evidence": {"proto": "tcp"}}, [])
    assert "threat_intel" in d["selected_agents"] and "correlation" in d["selected_agents"]

def test_high_alert_uses_deep_route():
    d = choose_route({"severity": "high", "evidence": {"proto": "tcp"}}, [])
    assert d["depth"] == "deep"


def test_dataset_severity_uses_observable_evidence_not_dataset_label():
    from app.orchestration.adaptive_router import evidence_based_severity
    alert = {"source": "dataset", "severity": "critical", "attack_category": "Fuzzers",
             "evidence": {"sbytes": 100, "dbytes": 200, "ct_dst_src_ltm": 1}}
    assert evidence_based_severity(alert) == "low"
