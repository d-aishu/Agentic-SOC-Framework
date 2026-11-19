"""UNSW-NB15 column definitions and category normalisation.

Two CSV layouts exist in the public download:

1. RAW files  ``UNSW-NB15_1.csv`` ... ``UNSW-NB15_4.csv``
   - NO header row, 49 columns, ~2.54 M records in total.
   - Contain source/destination IPs, ports and timestamps (Stime/Ltime).
2. PARTITIONED files ``UNSW_NB15_training-set.csv`` / ``UNSW_NB15_testing-set.csv``
   - Header row, ~45 columns (``id``, features, ``attack_cat``, ``label``).
   - NO IP addresses, NO ports, NO timestamps.

The code inspects the real file and never assumes a field exists.
"""
from __future__ import annotations

# Column order of the RAW files (lower-cased; the official list uses e.g. "Sload", "Stime", "Label").
RAW_COLUMNS: list[str] = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

IP_COLUMNS = ["srcip", "dstip"]
PORT_COLUMNS = ["sport", "dsport"]
TIME_COLUMNS = ["stime", "ltime"]
CATEGORICAL_COLUMNS = ["proto", "state", "service"]
LABEL_COLUMNS = ["attack_cat", "label"]
BINARY_COLUMNS = ["is_sm_ips_ports", "is_ftp_login"]
# Columns that must never be negative (negatives are treated as corrupt and set to 0).
NON_NEGATIVE_COLUMNS = ["dur", "sbytes", "dbytes", "spkts", "dpkts", "sloss", "dloss"]

# Columns added by this project (not numeric features).
META_COLUMNS = ["source_file", "source_row", "attack_cat_raw", "timestamp", "end_timestamp"]

NON_NUMERIC_COLUMNS = set(
    IP_COLUMNS + PORT_COLUMNS + TIME_COLUMNS + CATEGORICAL_COLUMNS + LABEL_COLUMNS + META_COLUMNS + ["id"]
)

# Canonical attack categories of UNSW-NB15 (+ "Unknown" for attack rows with no usable category).
ATTACK_CATEGORIES = [
    "Analysis", "Backdoor", "DoS", "Exploits", "Fuzzers",
    "Generic", "Reconnaissance", "Shellcode", "Worms",
]
NORMAL_CATEGORY = "Normal"
UNKNOWN_CATEGORY = "Unknown"

# Known spelling / whitespace inconsistencies in the raw files (keys are lower-case & stripped).
CATEGORY_ALIASES: dict[str, str] = {
    "normal": "Normal",
    "analysis": "Analysis",
    "backdoor": "Backdoor",
    "backdoors": "Backdoor",   # raw files use "Backdoors" in some rows
    "dos": "DoS",
    "exploits": "Exploits",
    "fuzzers": "Fuzzers",      # raw files contain " Fuzzers" with a leading space
    "generic": "Generic",
    "reconnaissance": "Reconnaissance",
    "shellcode": "Shellcode",
    "worms": "Worms",
}
