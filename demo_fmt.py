"""Formats adapter and mock-AIRS JSON log lines for demo.sh."""
import json, sys
from datetime import datetime

RED, GREEN, OFF = "\033[31m", "\033[32m", "\033[0m"
mode = sys.argv[1]
since = float(sys.argv[2]) if len(sys.argv) > 2 else 0
for line in sys.stdin:
    if since:
        ts, _, line = line.partition(" ")
        if datetime.fromisoformat(ts[:26].rstrip("Z") + "+00:00").timestamp() < since:
            continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    if mode == "verdicts":
        if e.get("event") == "airs_verdict":
            a = e["action"].upper()
            c = RED if a == "BLOCK" else GREEN
            print(f"  Prisma AIRS  {e['phase']:<8} {c}{a:<5}{OFF}  detected: {e['detected']:<10} scan_id {e['scan_id']}")
        elif e.get("event") == "airs_error":
            print(f"  {RED}Prisma AIRS unreachable:{OFF} {e['error']}")
    elif mode == "airs":
        pd, rd = e.get("prompt_detected"), e.get("response_detected")
        det = [k for d in (pd or {}, rd or {}) for k, v in d.items() if v]
        if pd is None:
            continue
        phase = "prompt"
        print(f"  user={str(e.get('app_user')):<8} {phase:<8} {e['action']:<5}  {','.join(det) or 'clean':<10} profile={e['profile']}")
