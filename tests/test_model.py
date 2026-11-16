import json
from pathlib import Path

from fetter_scope.events import own, parse_line
from fetter_scope.model import Model, alert_items, matches

from tests.test_digest import hook, pc, report, vuln

STREAMS = Path(__file__).parent / "fixtures" / "streams"


def loaded(*names, **kw) -> Model:
    m = Model(**kw)
    for n in names:
        for line in (STREAMS / f"{n}.jsonl").read_text().splitlines():
            m.add(parse_line(line))
    return m


def scan(t, counts, changes=None, trigger="period"):
    return parse_line(json.dumps({
        "schema": 1, "event": "scan", "time": {"secs": t, "nanos": 0}, "trigger": trigger,
        "origins": 1, "sites": 1, "packages": sum(c["packages"] for c in counts.values()),
        "counts": counts, "changes": changes or {}}))


def test_fixture_streams():
    m = loaded("quiet", "changes")
    assert [a.type for a in m.alerts].count("vuln") == 5 and len(m.alerts) == 6
    assert [(c.change, c.name, c.frm, c.to) for c in m.changes] == [
        ("added", "left-pad", "", "1.3.0"), ("downgraded", "lodash", "4.17.21", "4.17.15")]
    assert [(r.change, r.name, r.detail.split(" · ")[0]) for r in m.live] == [
        ("added", "left-pad", "1.3.0"), ("downgraded", "lodash", "4.17.21 → 4.17.15")]
    assert len(m.scans) == 5 and len(m.reports) == 3 and len(m.log) == 11
    assert m.fetter == "running" and m.period == 600
    assert m.next_scan_at() == m.last_scan["time"]["secs"] + 600 + m.last_scan["time"]["nanos"] / 1e9
    d = m.digest(0, 2e9)
    assert d["status"] == "alert" and d["counts"]["downgrades"] == 1


def test_attached_ignores_own_lifecycle():
    m = Model(attached=True)
    m.add(own("fetter-exit", code=1, expected=False))
    m.add(parse_line((STREAMS / "quiet.jsonl").read_text().splitlines()[0]))
    assert m.fetter == "attached"


def test_fetter_state():
    m = Model()
    assert m.fetter == "not running"
    m.add(own("launch", pid=1))
    assert m.fetter == "starting"
    m.add(parse_line((STREAMS / "quiet.jsonl").read_text().splitlines()[0]))
    assert m.fetter == "running"
    m.add(own("fetter-exit", code=1, expected=False, restart_in=5))
    assert m.fetter == "restarting"
    m.add(own("supervisor-error", message="x"))
    assert m.fetter == "failed"
    m.add(own("fetter-exit", code=0, expected=True))
    assert m.fetter == "not running"


def test_dropped_to_zero_and_feed_limit():
    m = Model(feed_limit=3)
    m.add(scan(1, {"npm": {"packages": 5}, "python": {"packages": 0}}))
    m.add(scan(2, {"npm": {"packages": 0}, "python": {"packages": 0}},
               {"packages": [pc("removed", f"p{i}", frm="1") for i in range(5)]}))
    assert m.dropped_to_zero() == ["npm"]
    assert [r.name for r in m.live] == ["p0", "p1", "p2"]       # capped; the oldest dropped
    m.add(scan(3, {"npm": {"packages": 4}}))
    assert m.dropped_to_zero() == []


def test_newer_schema_and_raw():
    m = Model()
    m.add(parse_line('{"schema": 2, "event": "scan", "time": {"secs": 1, "nanos": 0}}'))
    m.add(parse_line("not json"))
    assert m.newer == 2 and len(m.log) == 2 and len(m.entries) == 1


def test_alert_items_every_type():
    viol = {"ecosystem": "python", "package": "a", "dependency": None, "explain": "Unrequired",
            "sites": ["/s1", "/s2"]}
    r = report(0, "alert", new_vulns=[vuln("X", score=7.5)], hooks=[hook("added"), hook("removed")],
               packages=[pc("downgraded", "a", "2", "1"), pc("upgraded", "b", "1", "2")],
               new_violations=[viol])["report"]
    items = alert_items(r, 10.0)
    assert [(i.type, i.subject) for i in items] == [
        ("vuln", "lodash 1.0"), ("hook", "postinstall"), ("downgrade", "a"), ("violation", "a")]
    assert items[0].score == 7.5 and items[0].detail.startswith("X · CVSS 7.5 · introduced")
    assert items[2].detail == "2 → 1" and items[3].site == "/s1, /s2"
    assert len({i.key for i in items}) == 4
    assert items[0].site == ""                                   # before fetter 5.1.0: no sites
    r["new_vulns"][0]["sites"] = ["/p1", "/p2"]
    assert alert_items(r, 10.0)[0].site == "/p1, /p2"


def test_matches():
    f = {"kind": "downgraded", "eco": "npm", "site": "/home/u/proj", "name": "lodash"}
    assert matches("", f)
    assert matches("lod", f) and matches("kind:down eco:npm", f) and matches("PROJ", f)
    assert not matches("kind:added", f) and not matches("lodash react", f)
    assert matches("other:x", {"x": "other:x"})       # an unknown key is just a word


def test_same_advisory_at_two_versions_has_distinct_keys():
    m = Model()
    for _ in range(2):            # and across reports
        m.add(parse_line(json.dumps(report(0, "alert", new_vulns=[
            vuln("GHSA-same", version="4.17.21"), vuln("GHSA-same", version="4.17.15")],
            packages=[pc("added", "a", to="1"), pc("added", "a", to="1")]))))
    assert [a.key for a in m.alerts] == ["alert:0", "alert:1", "alert:2", "alert:3"]
    assert len({c.key for c in m.changes}) == 4
