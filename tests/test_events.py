import json
from pathlib import Path

import pytest

from fetter_scope.events import duration_seconds, parse_line

STREAMS = Path(__file__).parent / "fixtures" / "streams"
FIXTURES = sorted(STREAMS.glob("*.jsonl"))


def kinds(path):
    return [parse_line(line).kind for line in path.read_text().splitlines()]


def test_fixtures_present():
    assert {p.name for p in FIXTURES} >= {"quiet.jsonl", "changes.jsonl"}


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_fixture_parses(path):
    for line in path.read_text().splitlines():
        p = parse_line(line)
        assert p.known and not p.newer and not p.problem, line[:80]
        e = p.event
        assert e["schema"] == 1
        assert duration_seconds(e["time"]) > 1.7e9
        assert e["system"]["username"] == "user" and e["system"]["hostname"] == "host"


def test_quiet_stream():
    assert kinds(STREAMS / "quiet.jsonl") == ["start", "scan", "report", "scan", "report"]
    events = [parse_line(x).event for x in (STREAMS / "quiet.jsonl").read_text().splitlines()]
    start, first, baseline, rescan, unchanged = events
    assert start["baseline"] == "rolling" and start["control"] is True and "baseline_time" not in start
    assert first["trigger"] == "start" and first["counts"]["npm"]["packages"] == 1
    assert baseline["report"]["status"] == "alert"
    assert {v["source"] for v in baseline["report"]["new_vulns"]} == {"existing"}
    assert rescan["trigger"] == "request"
    assert unchanged["report"]["status"] == "unchanged"


def test_changes_stream():
    lines = (STREAMS / "changes.jsonl").read_text().splitlines()
    assert kinds(STREAMS / "changes.jsonl") == ["start", "scan", "scan", "scan", "report", "error"]
    events = [parse_line(x).event for x in lines]
    assert "baseline_time" in events[0]
    changes = {c["change"]: c for c in events[2]["changes"]["packages"]}
    assert set(changes) == {"added", "downgraded"}
    assert "from" not in changes["added"] and changes["added"]["to"]["key"] == "left-pad"
    assert (changes["downgraded"]["from"]["version"], changes["downgraded"]["to"]["version"]) == \
        ("4.17.21", "4.17.15")
    report = events[4]["report"]
    assert report["status"] == "alert"
    assert "introduced" in {v["source"] for v in report["new_vulns"]}
    assert all(isinstance(v["score"], float) for v in report["new_vulns"] if "score" in v)
    assert events[5]["message"].startswith("Unknown control command")


def base(**kw):
    return {"schema": 1, "event": "scan", "time": {"secs": 1, "nanos": 0},
            "system": {"hostname": "h"}, **kw}


def test_unknown_event():
    p = parse_line(json.dumps(base(event="checkpoint", x=1)))
    assert p.kind == "checkpoint" and not p.known and p.event["x"] == 1


def test_newer_schema():
    p = parse_line(json.dumps(base(schema=2)))
    assert p.known and p.newer and p.event["schema"] == 2


def test_extra_fields_kept():
    p = parse_line(json.dumps(base(trigger="period", future={"a": 1})))
    assert p.known and not p.newer and p.event["future"] == {"a": 1}


def test_unknown_trigger_is_kept():
    assert parse_line(json.dumps(base(trigger="timer"))).event["trigger"] == "timer"


@pytest.mark.parametrize("line,problem", [
    ("thread 'main' panicked at src/x.rs", "not JSON"),
    ("", "not JSON"),
    ("[1, 2]", "not a JSON object"),
    ('{"schema": 1}', "no event field"),
])
def test_raw_lines(line, problem):
    p = parse_line(line)
    assert p.kind == "raw" and p.event is None and p.line == line and problem in p.problem


def test_bad_schema_flagged():
    p = parse_line(json.dumps(base(schema="1")))
    assert p.known and not p.newer and "schema" in p.problem


def test_bytes_and_newline():
    p = parse_line(json.dumps(base()).encode() + b"\r\n")
    assert p.kind == "scan" and not p.line.endswith("\n")
    assert parse_line(b"\xff\xfe").kind == "raw"


def test_duration_seconds():
    assert duration_seconds({"secs": 2, "nanos": 500_000_000}) == 2.5
    assert duration_seconds({"secs": 2}) == 2
    assert duration_seconds(None) is None
    assert duration_seconds({"secs": "2"}) is None
