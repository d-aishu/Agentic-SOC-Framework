import pandas as pd

from app.alert_generation.severity import compute_severity
from app.preprocessing.cleaner import clean_dataframe, normalize_ip, parse_port
from app.schemas.alert import Severity


def test_parse_port_variants():
    assert parse_port("0x000b") == 11
    assert parse_port("80") == 80 and parse_port(80.0) == 80 and parse_port(" 443 ") == 443
    assert parse_port("-") is None and parse_port("") is None and parse_port(None) is None
    assert parse_port(70000) is None and parse_port(-1) is None and parse_port("abc") is None


def test_normalize_ip():
    assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert normalize_ip("999.1.1.1") is None and normalize_ip(None) is None


def test_severity_base_and_escalation():
    assert compute_severity("Normal", 10**9, 99)[0] == Severity.INFORMATIONAL      # never escalated
    assert compute_severity("Reconnaissance")[0] == Severity.LOW
    assert compute_severity("Exploits")[0] == Severity.HIGH
    assert compute_severity("Exploits", total_bytes=2_000_000)[0] == Severity.CRITICAL
    sev, why = compute_severity("Worms", 2_000_000, 40)
    assert sev == Severity.CRITICAL and "capped" in why
    assert compute_severity("Unknown")[0] == Severity.MEDIUM


def test_cleaner_category_normalisation_and_labels():
    df = pd.DataFrame({
        "attack_cat": [" Fuzzers", "Backdoors", None, "Normal", "Exploits", None],
        "label": [1, 1, 0, 0, 0, 1],
        "sport": ["0x000b", "-", "80", "81", "82", "83"],
    })
    out, stats = clean_dataframe(df, "t.csv")
    assert stats["dropped_conflicting_label"] == 1          # label 0 but Exploits
    assert set(out["attack_cat"]) == {"Fuzzers", "Backdoor", "Normal", "Unknown"}
    assert stats["attack_rows_without_category"] == 1       # label 1, blank category
    assert "attack_cat_raw" in out.columns and " Fuzzers" in set(out["attack_cat_raw"].dropna())
    assert out["sport"].iloc[0] == 11 and pd.isna(out["sport"].iloc[1])
    assert out["srcip"].isna().all() and out["timestamp"].isna().all()   # absent columns stay missing
