import shutil

import pytest
from fastapi.testclient import TestClient

from app.config.settings import Settings
from app.main import create_app
from scripts.make_sample_data import write_sample_raw_csv

API = "/api/v1"


@pytest.fixture()
def settings(tmp_path):
    return Settings(raw_data_dir=tmp_path / "raw", processed_data_dir=tmp_path / "processed",
                    log_dir=tmp_path / "logs", log_level="WARNING")


@pytest.fixture()
def sample_csv(tmp_path):
    path = tmp_path / "UNSW-NB15_1.csv"
    meta = write_sample_raw_csv(path)
    return path, meta


@pytest.fixture()
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


@pytest.fixture()
def uploaded(client, sample_csv):
    path, meta = sample_csv
    with path.open("rb") as fh:
        r = client.post(f"{API}/dataset/upload", files={"file": (path.name, fh, "text/csv")})
    assert r.status_code == 201, r.text
    return meta


@pytest.fixture()
def processed(client, uploaded):
    r = client.post(f"{API}/dataset/process")
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture()
def alerts_ready(client, processed):
    r = client.post(f"{API}/alerts/generate", json={"max_alerts": 100, "benign_fraction": 0.2, "seed": 1})
    assert r.status_code == 200, r.text
    return r.json()
