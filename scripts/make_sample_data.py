"""Create a SYNTHETIC file with the UNSW-NB15 RAW layout (49 columns, no header).

!! This is NOT real UNSW-NB15 data. It exists only to smoke-test the pipeline and the API
!! without downloading 2.5M rows. Never report results computed on it.

Usage:  python scripts/make_sample_data.py [output_path]
It deliberately includes the quirks of the real files (blank Normal categories, ' Fuzzers',
'Backdoors', hex/'-' ports, blank numeric cells, a duplicate row, bad rows).
"""
from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python scripts/...`

from app.dataset.columns import RAW_COLUMNS  # noqa: E402

COUNTS = {"Normal": 120, "Generic": 40, "Exploits": 40, "Fuzzers": 20, "DoS": 20,
          "Reconnaissance": 15, "Analysis": 6, "Backdoor": 6, "Shellcode": 5, "Worms": 3}
T0 = 1421927414


def _row(rng: random.Random, category: str, i: int) -> dict:
    attack = category != "Normal"
    dur = round(rng.uniform(0.0001, 12), 6)
    big = category in ("DoS", "Exploits") and rng.random() < 0.3
    sbytes = rng.randint(2_000_000, 6_000_000) if big else rng.randint(40, 9000)
    row = dict.fromkeys(RAW_COLUMNS, 0)
    row.update(
        srcip=f"175.45.176.{rng.randint(0, 3)}" if attack else f"59.166.0.{rng.randint(0, 9)}",
        sport=rng.randint(1024, 65000), dstip=f"149.171.126.{rng.randint(10, 19)}",
        dsport=rng.choice([80, 21, 22, 53, 25, 443, 6881]),
        proto=rng.choice(["tcp", "tcp", "udp", "icmp"]), state=rng.choice(["FIN", "CON", "INT"]),
        dur=dur, sbytes=sbytes, dbytes=rng.randint(0, 20000), sttl=62, dttl=252,
        service=rng.choice(["-", "http", "dns", "ftp", "smtp"]),
        sload=round(sbytes * 8 / max(dur, 1e-3), 2), dload=round(rng.uniform(0, 1e6), 2),
        spkts=rng.randint(1, 50), dpkts=rng.randint(0, 50), swin=255, dwin=255,
        stime=T0 + i, ltime=T0 + i + int(dur) + 1, tcprtt=round(rng.uniform(0, 0.1), 6),
        ct_state_ttl=rng.randint(0, 6), ct_srv_src=rng.randint(1, 20), ct_srv_dst=rng.randint(1, 20),
        ct_dst_ltm=rng.randint(1, 20), ct_src_ltm=rng.randint(1, 20),
        ct_dst_src_ltm=rng.randint(1, 45) if attack else rng.randint(1, 5),
        ct_flw_http_mthd="" , is_ftp_login="", ct_ftp_cmd=" ",
        attack_cat="" if not attack else category, label=1 if attack else 0,
    )
    if category == "Fuzzers" and i % 2 == 0:
        row["attack_cat"] = " Fuzzers"                 # leading space quirk
    if category == "Backdoor" and i % 2 == 0:
        row["attack_cat"] = "Backdoors"                # spelling quirk
    if row["proto"] == "icmp":
        row["sport"], row["dsport"] = "0x000b", "0x0000"   # hex ports quirk
    return row


def write_sample_raw_csv(path: Path, seed: int = 7) -> dict:
    """Write the file and return the expected cleaning outcome (used by the tests)."""
    rng = random.Random(seed)
    rows, i = [], 0
    for cat, n in COUNTS.items():
        for _ in range(n):
            rows.append(_row(rng, cat, i)); i += 1
    base = sum(COUNTS.values())

    rows[0]["sport"] = "-"                                           # missing port marker
    rows[1]["is_ftp_login"] = 4                                      # non-binary flag
    rows[2]["srcip"] = "999.1.1.1"                                   # invalid IP
    bad_label = {**rows[3], "label": "x"}                            # dropped: invalid label
    conflict = {**rows[4], "label": 0, "attack_cat": "Exploits"}     # dropped: label/category conflict
    duplicate = dict(rows[5])                                        # dropped: exact duplicate
    rows += [bad_label, conflict, duplicate]

    with Path(path).open("w", newline="", encoding="latin-1") as fh:
        writer = csv.writer(fh)
        for r in rows:
            writer.writerow([r[c] for c in RAW_COLUMNS])
    return {"rows_written": len(rows), "expected_rows_kept": base,
            "attack_rows": base - COUNTS["Normal"], "normal_rows": COUNTS["Normal"]}


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw/SYNTHETIC_unsw_raw_sample.csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    print(write_sample_raw_csv(out), "->", out)
