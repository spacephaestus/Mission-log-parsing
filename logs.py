#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import re
from collections import Counter
from typing import Iterable, List, Optional, Dict, Any

SEVERITY_ORDER = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

LINE_RE = re.compile(
    r"""
    ^\[(?P<ts>[^]]+)\]\s+            # [timestamp]
    (?P<sev>[A-Z]+)\s+               # SEVERITY
    (?P<msg>.*?)(?:\s+\(id=(?P<id>\d+)\))?$   # message and optional (id=...)
    """,
    re.VERBOSE,
)

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.rstrip("\n")
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        # Malformed line: skip or raise; we choose to skip gracefully
        return None
    ts_str = m.group("ts")
    sev = m.group("sev")
    msg = m.group("msg").strip()
    id_str = m.group("id")
    try:
        ts = dt.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    rec: Dict[str, Any] = {"timestamp": ts, "severity": sev, "message": msg}
    if id_str is not None:
        rec["id"] = int(id_str)
    return rec

def read_records(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return [r for r in (parse_line(l) for l in f) if r is not None]

def filter_records(
    recs: Iterable[Dict[str, Any]],
    severity: Optional[str] = None,
    packet_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    out = []
    for r in recs:
        if severity and r.get("severity") != severity:
            continue
        if packet_id is not None and r.get("id") != packet_id:
            continue
        out.append(r)
    return out

def summarize(recs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    recs = list(recs)
    counts = Counter(r["severity"] for r in recs)
    if recs:
        earliest = min(r["timestamp"] for r in recs)
        latest = max(r["timestamp"] for r in recs)
    else:
        earliest = latest = None
    return {
        "counts": dict(counts),
        "earliest": earliest.isoformat(sep=" ") if earliest else None,
        "latest":   latest.isoformat(sep=" ") if latest else None,
    }

def sort_records(recs: List[Dict[str, Any]], key: str, reverse: bool = False) -> List[Dict[str, Any]]:
    if key == "timestamp":
        return sorted(recs, key=lambda r: r["timestamp"], reverse=reverse)
    if key == "severity":
        return sorted(recs, key=lambda r: SEVERITY_RANK.get(r["severity"], -1), reverse=reverse)
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
    ap.add_argument("--json", action="store_true", help="output JSON for summary or lines")
    ap.add_argument("--sort", choices=["earliest", "latest", "severity"], help="sort output")
    args = ap.parse_args()

    recs = read_records(args.path)
    recs = filter_records(recs, severity=args.severity, packet_id=args.packet_id)

    # Sorting logic
    if args.sort == "earliest":
        recs = sort_records(recs, key="timestamp", reverse=False)
    elif args.sort == "latest":
        recs = sort_records(recs, key="timestamp", reverse=True)
    elif args.sort == "severity":
        recs = sort_records(recs, key="severity", reverse=True)  # highest first

    if args.summary:
        s = summarize(recs)
        if args.json:
            print(json.dumps(s, indent=2))
        else:
            counts_str = ", ".join(f"{k}:{v}" for k, v in sorted(s["counts"].items(), key=lambda kv: SEVERITY_RANK[kv[0]]))
            print(f"Counts: {counts_str}")
            print(f"Earliest: {s['earliest']}")
            print(f"Latest:   {s['latest']}")
    else:
        if args.json:
            print(json.dumps([{
                "timestamp": r["timestamp"].isoformat(sep=" "),
                "severity": r["severity"],
                "message": r["message"],
                **({"id": r["id"]} if "id" in r else {}),
            } for r in recs], indent=2))
        else:
            for r in recs:
                print(format_record(r))

if __name__ == "__main__":
    main()
