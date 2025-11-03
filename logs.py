#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from typing import Iterable, List, Optional, Dict, Any

# Accept both WARN and WARNING; standard order lowest -> highest
SEVERITY_ORDER = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"]
# Treat WARN and WARNING at the same rank for sorting; both map to WARNING level
_SEV_BASE_RANK = {"DEBUG": 0, "INFO": 1, "WARN": 2, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

def _sev_rank(sev: str) -> int:
    return _SEV_BASE_RANK.get(sev.upper(), -1)

# Regex: [timestamp] SEVERITY message (optional (id=...))
LINE_RE = re.compile(
    r"""
    ^\[(?P<ts>[^\]]+)\]\s+            # [timestamp]
    (?P<sev>[A-Za-z]+)\s+             # severity word
    (?P<msg>.*?)(?:\s+\(id=(?P<id>\d+)\))?\s*$  # message + optional id
    """,
    re.VERBOSE,
)

def parse_ts(ts_str: str) -> Optional[dt.datetime]:
    """Try multiple timestamp formats: with/without ms, ISO 'T', with/without TZ."""
    s = ts_str.strip()
    # Convert trailing Z to +00:00 for %z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Convert ...+05:30 to +0530 for %z compatibility
    if len(s) >= 6 and (s[-6] in ["+", "-"]) and s[-3] == ":":
        s = s[:-6] + s[-6:-3] + s[-2:]

    fmts = [
        "%Y-%m-%d %H:%M:%S",         # 2025-10-19 12:05:25
        "%Y-%m-%d %H:%M:%S.%f",      # 2025-10-19 12:05:25.123
        "%Y-%m-%dT%H:%M:%S",         # 2025-10-19T12:05:25
        "%Y-%m-%dT%H:%M:%S.%f",      # 2025-10-19T12:05:25.123
        "%Y-%m-%d %H:%M:%S%z",       # with timezone
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ]
    for fmt in fmts:
        try:
            return dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.rstrip("\r\n")
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None
    ts = parse_ts(m.group("ts"))
    if ts is None:
        return None
    sev = m.group("sev").upper()
    msg = m.group("msg").strip()
    id_str = m.group("id")
    rec: Dict[str, Any] = {"timestamp": ts, "severity": sev, "message": msg}
    if id_str is not None:
        rec["id"] = int(id_str)
    return rec

def read_records(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            r = parse_line(line)
            if r is not None:
                out.append(r)
    return out

def filter_records(
    recs: Iterable[Dict[str, Any]],
    severity: Optional[str] = None,
    packet_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in recs:
        if severity and r.get("severity") != severity:
            continue
        if packet_id is not None and r.get("id") != packet_id:
            continue
        out.append(r)
    return out

def summarize(recs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    recs_list = list(recs)
    counts = Counter(r["severity"] for r in recs_list)
    if recs_list:
        earliest_dt = min(r["timestamp"] for r in recs_list)
        latest_dt   = max(r["timestamp"] for r in recs_list)
        earliest = earliest_dt.strftime("%Y-%m-%d %H:%M:%S")
        latest   = latest_dt.strftime("%Y-%m-%d %H:%M:%S")
    else:
        earliest = latest = None
    return {"counts": dict(counts), "earliest": earliest, "latest": latest}

def sort_records(recs: List[Dict[str, Any]], key: str, reverse: bool = False) -> List[Dict[str, Any]]:
    if key == "timestamp":
        return sorted(recs, key=lambda r: r["timestamp"], reverse=reverse)
    if key == "severity":
        return sorted(recs, key=lambda r: _sev_rank(r.get("severity", "")), reverse=reverse)
    return recs

def format_record(r: Dict[str, Any]) -> str:
    ts = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    sev = r["severity"]
    msg = r["message"]
    if "id" in r:
        return f"[{ts}] {sev} {msg} (id={r['id']})"
    return f"[{ts}] {sev} {msg}"

def main():
    ap = argparse.ArgumentParser(description="Mission log filter and summarizer")
    ap.add_argument("path", help="path to log file")
    ap.add_argument("--severity", choices=SEVERITY_ORDER, help="filter by severity")
    ap.add_argument("--id", type=int, dest="packet_id", help="filter by packet/command id")
    ap.add_argument("--summary", action="store_true", help="print counts and earliest/latest")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--sort", choices=["earliest", "latest", "severity"], help="sort output")
    ap.add_argument("--debug", action="store_true", help="print lines that fail to parse")
    args = ap.parse_args()

    if args.debug:
        with open(args.path, "r", encoding="utf-8") as f:
            for i, raw in enumerate(f, start=1):
                if parse_line(raw) is None:
                    sys.stderr.write(f"[DEBUG] Unparsed line {i}: {raw}")

    recs = read_records(args.path)

    # Sorting choice maps
    if args.sort == "earliest":
        recs = sort_records(recs, key="timestamp", reverse=False)
    elif args.sort == "latest":
        recs = sort_records(recs, key="timestamp", reverse=True)
    elif args.sort == "severity":
        recs = sort_records(recs, key="severity", reverse=True)

    # Apply filters after reading (but before printing/summary)
    recs = filter_records(recs, severity=args.severity, packet_id=args.packet_id)

    if args.summary:
        s = summarize(recs)
        if args.json:
            print(json.dumps(s, indent=2))
        else:
            ordered_counts = sorted(s["counts"].items(), key=lambda kv: _sev_rank(kv[0]))
            counts_str = ", ".join(f"{k}:{v}" for k, v in ordered_counts)
            print("Counts:", counts_str)
            print(f"Earliest: {s['earliest']}")
            print(f"Latest:   {s['latest']}")
    else:
        if args.json:
            print(json.dumps([
                {
                    "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": r["severity"],
                    "message": r["message"],
                    **({"id": r["id"]} if "id" in r else {}),
                } for r in recs
            ], indent=2))
        else:
            for r in recs:
                print(format_record(r))

if __name__ == "__main__":
    main()
