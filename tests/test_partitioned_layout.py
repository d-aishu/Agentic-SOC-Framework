"""The training/testing-set layout has NO IPs, ports or timestamps: alerts must carry nulls, not invented values."""
API = "/api/v1"

CSV = (
    "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,sttl,dttl,sload,dload,sloss,dloss,"
    "sinpkt,dinpkt,sjit,djit,swin,stcpb,dtcpb,dwin,tcprtt,synack,ackdat,smean,dmean,trans_depth,"
    "response_body_len,ct_srv_src,ct_state_ttl,ct_dst_ltm,ct_src_dport_ltm,ct_dst_sport_ltm,"
    "ct_dst_src_ltm,is_ftp_login,ct_ftp_cmd,ct_flw_http_mthd,ct_src_ltm,ct_srv_dst,is_sm_ips_ports,"
    "attack_cat,label\n"
    "1,0.5,tcp,http,FIN,10,8,900,1200,30,62,252,1000,2000,0,0,1,1,0,0,255,0,0,255,0,0,0,90,150,0,0,3,0,2,1,1,2,0,0,0,2,3,0,Exploits,1\n"
    "2,0.1,udp,dns,CON,2,2,100,200,60,31,29,500,800,0,0,1,1,0,0,0,0,0,0,0,0,0,50,100,0,0,1,0,1,1,1,1,0,0,0,1,1,0,Normal,0\n"
)


def test_partitioned_file_flow(client):
    r = client.post(f"{API}/dataset/upload", files={"file": ("UNSW_NB15_training-set.csv", CSV.encode(), "text/csv")})
    assert r.status_code == 201 and r.json()["kind"] == "partitioned"

    s = client.post(f"{API}/dataset/process").json()
    assert s["dataset_kind"] == "partitioned"
    assert not s["has_ip_addresses"] and not s["has_ports"] and not s["has_timestamps"]
    assert len(s["notes"]) == 3

    assert client.post(f"{API}/alerts/generate", json={"benign_fraction": 0.5, "max_alerts": 2}).status_code == 200
    a = client.get(f"{API}/alerts/ALR-000001").json()
    assert a["source_ip"] is None and a["destination_port"] is None and a["timestamp"] is None
    assert "unknown endpoint" in a["evidence_summary"]


def test_mixed_layouts_rejected(client, uploaded):
    client.post(f"{API}/dataset/upload", files={"file": ("UNSW_NB15_testing-set.csv", CSV.encode(), "text/csv")})
    r = client.post(f"{API}/dataset/process")
    assert r.status_code == 422 and "cannot be mixed" in r.json()["error"]["message"]
