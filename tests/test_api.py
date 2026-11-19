API = "/api/v1"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


# ---------------------------------------------------------------- dataset
def test_upload_rejects_non_csv(client):
    r = client.post(f"{API}/dataset/upload", files={"file": ("x.txt", b"a,b", "text/plain")})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"


def test_upload_rejects_non_unsw_csv(client):
    r = client.post(f"{API}/dataset/upload", files={"file": ("x.csv", b"a,b,c\n1,2,3\n", "text/csv")})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_dataset"
    assert client.get(f"{API}/dataset/files").json()["files"] == []   # rejected file removed


def test_upload_and_list_files(client, uploaded):
    files = client.get(f"{API}/dataset/files").json()["files"]
    assert len(files) == 1
    f = files[0]
    assert f["kind"] == "raw_no_header" and f["processable"] and f["n_columns"] == 49
    assert f["columns"][0] == "srcip" and f["columns"][-1] == "label"


def test_process_without_files_is_404(client):
    r = client.post(f"{API}/dataset/process")
    assert r.status_code == 404 and r.json()["error"]["code"] == "dataset_not_found"


def test_process_rejects_path_traversal_and_missing_file(client, uploaded):
    assert client.post(f"{API}/dataset/process", json={"files": ["../x.csv"]}).status_code == 422
    assert client.post(f"{API}/dataset/process", json={"files": ["nope.csv"]}).status_code == 404


def test_process_and_summary(client, uploaded):
    assert client.get(f"{API}/dataset/summary").status_code == 409       # not processed yet
    s = client.post(f"{API}/dataset/process").json()
    assert s["rows_in"] == uploaded["rows_written"]
    assert s["rows_out"] == uploaded["expected_rows_kept"]
    assert s["label_distribution"] == {"normal": uploaded["normal_rows"], "attack": uploaded["attack_rows"]}
    q = s["data_quality"]
    assert q["dropped_invalid_label"] == 1 and q["dropped_conflicting_label"] == 1 and q["dropped_duplicates"] == 1
    assert "Backdoor" in s["category_distribution"] and not any(k.startswith(" ") for k in s["category_distribution"])
    assert s["has_ip_addresses"] and s["has_timestamps"]
    assert client.get(f"{API}/dataset/summary").json()["rows_out"] == s["rows_out"]


def test_process_max_rows(client, uploaded):
    s = client.post(f"{API}/dataset/process", json={"max_rows_per_file": 50}).json()
    assert s["rows_in"] == 50
    assert client.post(f"{API}/dataset/process", json={"max_rows_per_file": 0}).status_code == 422


# ---------------------------------------------------------------- alerts
def test_generate_requires_processed_dataset(client):
    r = client.post(f"{API}/alerts/generate", json={})
    assert r.status_code == 409 and r.json()["error"]["code"] == "dataset_not_processed"


def test_generate_validation_errors(client, processed):
    assert client.post(f"{API}/alerts/generate", json={"max_alerts": 0}).status_code == 422
    assert client.post(f"{API}/alerts/generate", json={"benign_fraction": 0.95}).status_code == 422
    assert client.post(f"{API}/alerts/generate", json={"strategy": "bogus"}).status_code == 422
    r = client.post(f"{API}/alerts/generate", json={"categories": ["NotACategory"]})
    assert r.status_code == 422 and "Valid values" in r.json()["error"]["message"]


def test_generate_balanced_and_benign(client, processed):
    r = client.post(f"{API}/alerts/generate", json={"max_alerts": 50, "benign_fraction": 0.2}).json()
    assert r["generated"] == 50 and r["benign_included"] == 10
    attack_cats = {k for k in r["by_category"] if k != "Normal"}
    assert {"Worms", "Shellcode", "Backdoor"} <= attack_cats          # balanced sampling keeps rare classes


def test_generate_category_filter_and_append(client, processed):
    r = client.post(f"{API}/alerts/generate", json={"categories": ["worms", "DoS"], "max_alerts": 1000}).json()
    assert set(r["by_category"]) == {"Worms", "DoS"} and r["generated"] == 23
    r2 = client.post(f"{API}/alerts/generate", json={"categories": ["Worms"], "replace_existing": False}).json()
    assert r2["total_alerts_now"] == 23 + 3
    assert client.get(f"{API}/alerts/ALR-000024").status_code == 200   # ids continue after append


def test_generate_is_reproducible(client, processed):
    body = {"max_alerts": 30, "strategy": "random", "seed": 5}
    client.post(f"{API}/alerts/generate", json=body)
    a = client.get(f"{API}/alerts?limit=1000").json()["items"]
    client.post(f"{API}/alerts/generate", json=body)
    b = client.get(f"{API}/alerts?limit=1000").json()["items"]
    assert [x["record_ref"] for x in a] == [x["record_ref"] for x in b]


def test_list_alerts_and_pagination(client, alerts_ready):
    page = client.get(f"{API}/alerts?limit=10").json()
    assert page["total"] == 100 and len(page["items"]) == 10
    page2 = client.get(f"{API}/alerts?limit=10&skip=95").json()
    assert len(page2["items"]) == 5
    assert client.get(f"{API}/alerts?limit=0").status_code == 422


def test_filters(client, alerts_ready):
    items = client.get(f"{API}/alerts?attack_category=exploits&limit=1000").json()["items"]
    assert items and all(a["attack_category"] == "Exploits" for a in items)
    items = client.get(f"{API}/alerts?severity=critical&limit=1000").json()["items"]
    assert items and all(a["severity"] == "critical" for a in items)
    both = client.get(f"{API}/alerts?attack_category=Worms&severity=critical").json()
    assert both["total"] == len(both["items"]) and all(a["attack_category"] == "Worms" for a in both["items"])
    assert client.get(f"{API}/alerts?severity=bogus").status_code == 422
    assert client.get(f"{API}/alerts?attack_category=Nothing").json()["total"] == 0
    assert client.get(f"{API}/alerts?source=dataset&limit=1").json()["total"] == 100


def test_alert_fields(client, alerts_ready):
    items = client.get(f"{API}/alerts?limit=1000").json()["items"]
    a = next(x for x in items if x["source_ip"])      # one sample row has a deliberately invalid IP -> null
    for key in ("alert_id", "timestamp", "source", "source_ip", "destination_ip", "protocol", "source_port",
                "destination_port", "attack_category", "severity", "description"):
        assert key in a
    assert a["source"] == "dataset" and a["detection_method"] == "dataset_label"
    assert a["source_ip"] and a["timestamp"] and "sbytes" in a["evidence"]


def test_get_alert_not_found(client, alerts_ready):
    r = client.get(f"{API}/alerts/ALR-999999")
    assert r.status_code == 404 and r.json()["error"]["code"] == "alert_not_found"


def test_agent_view_has_no_ground_truth(client, alerts_ready):
    v = client.get(f"{API}/alerts/ALR-000001/agent-view").json()
    for forbidden in ("attack_category", "severity", "severity_rationale", "description",
                      "label", "record_ref", "detection_method"):
        assert forbidden not in v
    text = (v["evidence_summary"] + str(v["evidence"])).lower()
    for cat in ("exploits", "fuzzers", "worms", "backdoor", "shellcode", "reconnaissance", "generic", "analysis"):
        assert cat not in text
    assert client.get(f"{API}/alerts/ALR-999999/agent-view").status_code == 404


def test_stats(client, alerts_ready):
    s = client.get(f"{API}/alerts/stats").json()
    assert s["total"] == 100 and sum(s["by_category"].values()) == 100
    assert sum(s["by_severity"].values()) == 100 and s["by_source"] == {"dataset": 100}
    assert s["time_range"]["first"] <= s["time_range"]["last"]
    assert sum(sum(v.values()) for v in s["severity_by_category"].values()) == 100
    assert s["by_severity"].get("informational") == 20           # the 20% benign flows


def test_stats_empty(client):
    assert client.get(f"{API}/alerts/stats").json()["total"] == 0


def test_ground_truth_endpoint(client, alerts_ready):
    alerts = client.get(f"{API}/alerts?limit=1000").json()["items"]
    for a in alerts:
        t = client.get(f"{API}/evaluation/ground-truth/{a['alert_id']}").json()
        assert t["attack_category"] == a["attack_category"]
        assert t["label"] == (0 if a["attack_category"] == "Normal" else 1)
    assert client.get(f"{API}/evaluation/ground-truth/ALR-999999").status_code == 404


def test_clear_alerts(client, alerts_ready):
    assert client.delete(f"{API}/alerts").json() == {"deleted": 100}
    assert client.get(f"{API}/alerts").json()["total"] == 0


def test_persistence_across_restart(settings, alerts_ready, client):
    from fastapi.testclient import TestClient
    from app.main import create_app
    with TestClient(create_app(settings)) as c2:
        assert c2.get(f"{API}/alerts").json()["total"] == 100
        assert c2.get(f"{API}/dataset/summary").status_code == 200
        assert c2.get(f"{API}/evaluation/ground-truth/ALR-000001").status_code == 200


def test_unknown_route_uses_error_envelope(client):
    r = client.get("/nope")
    assert r.status_code == 404 and r.json()["error"]["code"] == "http_error"
