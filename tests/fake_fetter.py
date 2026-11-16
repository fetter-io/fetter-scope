"""A stand-in for `fetter ... monitor-diff ... --control stdin json` in tests.

Prints `start` and a `start` scan (or replays a fixture), then answers control commands on stdin
like fetter: `scan` → a `request` scan; `report` → a `request` scan and a report; `stop` → exit;
anything else → an `Unknown control command` error. At end of input it keeps running, as fetter
does (a closed stdin is not a stop). fetter's own arguments are accepted and ignored.

Behaviour flags (all `--fake-*`) make it misbehave for supervisor tests.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

SYSTEM = {"username": "user", "hostname": "host", "os_name": "linux", "os_version": "24.04",
          "architecture": "x86_64", "logical_cores": 4}
EMPTY = {"origins": [], "sites": [], "packages": [], "hooks": []}


def event(kind: str, **fields) -> dict:
    t = time.time()
    return {"schema": 1, "time": {"secs": int(t), "nanos": int((t % 1) * 1e9)},
            "system": SYSTEM, "event": kind, **fields}


def emit(obj) -> None:
    print(obj if isinstance(obj, str) else json.dumps(obj), flush=True)


def scan(trigger: str) -> dict:
    return event("scan", trigger=trigger, origins=1, sites=1, packages=1,
                 counts={"npm": {"origins": 1, "sites": 1, "packages": 1}}, changes=EMPTY)


def report(status: str) -> dict:
    t = event("x")["time"]
    return event("report", report={"status": status, "time": t, "changes": EMPTY,
                                   "new_vulns": [], "resolved_vulns": []})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--fake-version", default="5.1.0")
    ap.add_argument("--fake-runs", help="a counter file, incremented at each launch")
    ap.add_argument("--fake-fail-first", type=int, default=0,
                    help="on the first N launches, print start then exit before any scan")
    ap.add_argument("--fake-exit-code", type=int, default=1)
    ap.add_argument("--fake-stop-code", type=int, default=0)
    ap.add_argument("--fake-ignore-stop", action="store_true")
    ap.add_argument("--fake-close-stdin", action="store_true")
    ap.add_argument("--fake-no-report", action="store_true", help="`report` writes no report")
    ap.add_argument("--fake-report-status", default="changed")
    ap.add_argument("--fake-misread", action="store_true", help="treat every command as unknown")
    ap.add_argument("--fake-delay", type=float, default=0, help="seconds before each reply")
    ap.add_argument("--fake-stderr")
    ap.add_argument("--fake-raw", help="a non-JSON stdout line after the start scan")
    ap.add_argument("--fake-replay", help="a stream file printed in place of start and scan")
    args, _ = ap.parse_known_args()

    if args.version:
        print(f"fetter {args.fake_version}")
        return 0

    run = 1
    if args.fake_runs:
        counter = Path(args.fake_runs)
        run = int(counter.read_text() or 0) + 1 if counter.exists() else 1
        counter.write_text(str(run))

    if args.fake_stderr:
        print(args.fake_stderr, file=sys.stderr, flush=True)
    if args.fake_replay:
        for line in Path(args.fake_replay).read_text().splitlines():
            emit(line)
    else:
        emit(event("start", baseline="rolling", period=300, report_period=300,
                   ecosystems=["npm"], control=True))
        if run <= args.fake_fail_first:
            return args.fake_exit_code
        emit(scan("start"))
    if args.fake_raw:
        emit(args.fake_raw)

    if args.fake_close_stdin:
        os.close(0)
        while True:
            time.sleep(1)

    for line in sys.stdin:
        cmd = line.strip()
        if not cmd:
            continue
        time.sleep(args.fake_delay)
        if args.fake_misread or cmd not in ("scan", "report", "stop"):
            emit(event("error", message=f"Unknown control command: {cmd!r} "
                                        "(expected scan, report, or stop)"))
        elif cmd == "scan":
            emit(scan("request"))
        elif cmd == "report":
            emit(scan("request"))
            if not args.fake_no_report:
                emit(report(args.fake_report_status))
        elif cmd == "stop" and not args.fake_ignore_stop:
            return args.fake_stop_code
    while True:                       # stdin closed: keep running, as fetter does
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
