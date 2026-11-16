import json

from fetter_scope.events import parse_line
from fetter_scope.home import Home
from fetter_scope.sites import UNNAMED, Inventory, open_inventory, site_rows
from fetter_scope.store import Store

from tests.test_digest import T, T0, pc, pkg, vuln
from tests.test_digest import report as _report


def report(t: float, *a, established=False, **kw) -> dict:
    """A report against a rolling baseline set at 0; `established`: the first, which sets it."""
    e = _report(t, *a, **kw)
    e["report"]["baseline_time"] = None if established else T(0)
    return e


def start(t: float, baseline="rolling") -> dict:
    return {"schema": 1, "event": "start", "time": {"secs": int(T0 + t), "nanos": 0},
            "baseline": baseline, "period": 600}


def at(v: dict, *sites: str) -> dict:
    return v | {"sites": list(sites)}


def resolved(key: str, version: str, id_: str) -> dict:
    return {"package": pkg(key, version), "id": id_}


def inv(*events) -> Inventory:
    i = Inventory()
    i.apply_all(events)
    return i


def test_open_is_new_minus_resolved_across_reports():
    i = inv(start(0),
            report(10, "alert", new_vulns=[at(vuln("A", score=9.8), "/p"),
                                           at(vuln("B", key="x", score=5.0), "/p", "/q")]),
            report(20, resolved_vulns=[resolved("lodash", "1.0", "A")]),
            report(30, "alert", new_vulns=[at(vuln("C", key="y"), "/q")]))
    assert sorted(v["id"] for v in i.vulns.values()) == ["B", "C"]
    assert i.through == T0 + 30
    [b] = [v for v in i.vulns.values() if v["id"] == "B"]
    assert b["first"] == T0 + 10 and b["sites"] == ["/p", "/q"]


def test_resolved_matches_by_version():
    # the advisory at 1.0 resolved; the same advisory at 2.0 stays open
    i = inv(report(10, "alert", new_vulns=[at(vuln("A", version="1.0"), "/a"),
                                           at(vuln("A", version="2.0"), "/b")]),
            report(20, resolved_vulns=[resolved("lodash", "1.0", "A")]))
    assert [v["package"]["version"] for v in i.vulns.values()] == ["2.0"]


def test_reapplying_is_a_no_op():
    r1 = report(10, "alert", new_vulns=[at(vuln("A"), "/p")])
    r2 = report(20, resolved_vulns=[resolved("lodash", "1.0", "A")])
    i = inv(r1, r2)
    assert not i.apply(r1) and not i.vulns          # an earlier report does not reopen A


def test_fixed_baseline_replaces_the_set():
    i = inv(start(0, baseline="/b.json"),
            report(10, "alert", new_vulns=[at(vuln("A"), "/p"), at(vuln("B", key="x"), "/p")]),
            report(20, "alert", new_vulns=[at(vuln("B", key="x"), "/p")]))
    [b] = i.vulns.values()
    assert b["id"] == "B" and b["first"] == T0 + 10


def test_sites_from_changes_and_removal():
    site = {"ecosystem": "npm", "path": "/gone", "kind": "installed"}
    i = inv(report(10, packages=[pc("added", "a", to="1.0", site="/p")],
                   sites=[site | {"change": "added"}]),
            report(20, sites=[site | {"change": "removed"}]))
    assert [(s["path"], s["changed"]) for s in i.sites.values()] == [("/p", T0 + 10)]


def test_site_rows_summary_and_order():
    i = inv(report(10, "alert", packages=[pc("added", "z", to="1", site="/quiet")], new_vulns=[
        at(vuln("A", score=9.8), "/p"), at(vuln("B", key="x", score=7.5), "/p"),
        at(vuln("C", key="y", score=4.0), "/p"), at(vuln("D", key="y"), "/p"),
        at(vuln("E", key="w", score=7.0), "/q"),
        vuln("F", key="old", score=5.0)]))                       # no sites: before fetter 5.1.0
    rows = site_rows(i)
    assert [r.path for r in rows] == ["/p", "/q", UNNAMED, "/quiet"]
    p = rows[0]
    assert (p.open, p.max, p.median, p.critical, p.high, p.unscored, p.packages) == (
        4, 9.8, 7.5, 1, 1, 1, 3)
    assert [v["id"] for v in p.vulns] == ["A", "B", "C", "D"]     # highest CVSS first
    quiet = rows[-1]
    assert quiet.open == 0 and quiet.max is None and quiet.changed == T0 + 10


def test_save_load_and_top_up_from_events(tmp_path):
    home = Home(tmp_path)
    store = Store(home, now=lambda: T0 + 100)     # day files by the events' clock
    for e in (start(0), report(10, "alert", new_vulns=[at(vuln("A"), "/p")])):
        store.append(parse_line(json.dumps(e)))
    i = open_inventory(store)                                     # rebuilt from events
    assert [v["id"] for v in i.vulns.values()] == ["A"]
    i.save(home.sites)
    # events/ pruned, a later report stored: the saved set plus what came after
    for f in store.event_files():
        f.unlink()
    store.close()
    store.append(parse_line(json.dumps(report(20, "alert", new_vulns=[at(vuln("B", key="x"), "/q")]))))
    j = open_inventory(store)
    assert sorted(v["id"] for v in j.vulns.values()) == ["A", "B"] and j.through == T0 + 20


def test_unreadable_or_other_schema_starts_empty(tmp_path):
    p = tmp_path / "sites.json"
    p.write_text("{not json")
    assert Inventory.load(p).vulns == {}
    p.write_text(json.dumps({"schema": 99, "vulns": [vuln("A")]}))
    assert Inventory.load(p).vulns == {}


def test_established_baseline_replaces_the_set_unless_the_audit_failed():
    # fetter 5.0.0 history (no sites), then the rolling baseline removed under 5.1.0: the report
    # re-establishing it lists every existing vulnerability, now with sites; the stale one goes
    i = inv(report(10, "alert", new_vulns=[vuln("A"), vuln("B", key="x")]))
    failed = report(20, "alert", established=True, audit_error="OSV timed out")
    assert i.apply(failed) and len(i.vulns) == 2                 # incomplete: nothing dropped
    i.apply(report(30, "alert", established=True,
                   new_vulns=[at(vuln("A", source="existing"), "/p")]))
    [a] = i.vulns.values()
    assert a["id"] == "A" and a["sites"] == ["/p"] and a["first"] == T0 + 10
