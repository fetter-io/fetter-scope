from pathlib import Path

import pytest

from fetter_scope.digest import fold, pending_window
from fetter_scope.events import own, parse_line

STREAMS = Path(__file__).parent / "fixtures" / "streams"
T0 = 1_800_000_000


def T(t: float) -> dict:
    return {"secs": int(T0 + t), "nanos": 0}


def pkg(key: str, version: str) -> dict:
    return {"ecosystem": "npm", "name": key, "key": key, "version": version, "direct_url": None}


def pc(change: str, key: str, frm: str | None = None, to: str | None = None, site="/p") -> dict:
    c = {"change": change, "ecosystem": "npm", "site": site}
    if frm:
        c["from"] = pkg(key, frm)
    if to:
        c["to"] = pkg(key, to)
    return c


def hook(change: str, name="postinstall", detail="node x.js") -> dict:
    return {"change": change, "ecosystem": "npm", "site": "/p",
            "hook": {"name": name, "detail": detail}}


def vuln(id_: str, key="lodash", version="1.0", source="introduced", score=None) -> dict:
    v = {"package": pkg(key, version), "id": id_, "source": source, "url": f"https://osv.dev/{id_}"}
    if score is not None:
        v["score"] = score
    return v


def report(t: float, status="changed", packages=(), hooks=(), origins=(), sites=(),
           new_vulns=(), resolved_vulns=(), new_violations=(), resolved_violations=(),
           audit_error=None) -> dict:
    r = {"status": status, "time": T(t),
         "changes": {"origins": list(origins), "sites": list(sites), "packages": list(packages),
                     "hooks": list(hooks)},
         "new_vulns": list(new_vulns), "resolved_vulns": list(resolved_vulns)}
    if new_violations:
        r["new_violations"] = list(new_violations)
    if resolved_violations:
        r["resolved_violations"] = list(resolved_violations)
    if audit_error:
        r["audit_error"] = audit_error
    return {"schema": 1, "event": "report", "time": T(t), "system": {"hostname": "host"}, "report": r}


def scan(t: float) -> dict:
    return {"schema": 1, "event": "scan", "time": T(t), "trigger": "period", "origins": 1,
            "sites": 1, "packages": 3, "counts": {}, "changes": {}}


def start(t: float, baseline="rolling", period=300) -> dict:
    return {"schema": 1, "event": "start", "time": T(t), "baseline": baseline, "period": period,
            "report_period": period, "ecosystems": ["npm"], "control": True}


def run(*entries, period=None, baseline="rolling", window=(0, 10_000)):
    return fold(entries, T0 + window[0], T0 + window[1], period=period, baseline=baseline)


# packages ---------------------------------------------------------------------

def test_upgrade_then_downgrade_back_is_transient():
    d = run(report(10, packages=[pc("upgraded", "a", "1.0", "2.0")]),
            report(20, "alert", packages=[pc("downgraded", "a", "2.0", "1.0")]))
    assert d["packages"] == []
    [t] = d["transient"]["packages"]
    assert t["what"] == "changed then restored" and t["versions"] == ["1.0", "2.0", "1.0"]
    assert (t["first"], t["last"]) == (T0 + 10, T0 + 20)


def test_added_then_removed_is_transient():
    d = run(report(10, packages=[pc("added", "a", to="1.0")]),
            report(20, packages=[pc("removed", "a", frm="1.0")]))
    assert d["packages"] == []
    [t] = d["transient"]["packages"]
    assert t["what"] == "installed then removed" and t["versions"] == ["(none)", "1.0", "(none)"]


def test_added_then_upgraded_is_added_at_final_version():
    d = run(report(10, packages=[pc("added", "a", to="1.0")]),
            report(20, packages=[pc("upgraded", "a", "1.0", "2.0")]))
    [p] = d["packages"]
    assert p["change"] == "added" and p["from"] is None and p["to"]["version"] == "2.0"
    assert p["steps"] == 2


@pytest.mark.parametrize("steps,expect", [
    ([("upgraded", "1", "2")], "upgraded"),
    ([("upgraded", "1", "2"), ("upgraded", "2", "3")], "upgraded"),
    ([("downgraded", "3", "2"), ("downgraded", "2", "1")], "downgraded"),
    ([("upgraded", "1", "3"), ("downgraded", "3", "2")], "changed"),       # 1 → 2: not ordered here
    ([("upgraded", "1", "2"), ("downgraded", "2", "1"), ("upgraded", "1", "3")], "upgraded"),
    ([("downgraded", "2", "1"), ("upgraded", "1", "2"), ("downgraded", "2", "0")], "downgraded"),
    ([("changed", "v1", "v2")], "changed"),
])
def test_net_kind_from_fetter_steps(steps, expect):
    d = run(*(report(10 * i, packages=[pc(k, "a", f, t)]) for i, (k, f, t) in enumerate(steps, 1)))
    [p] = d["packages"]
    assert p["change"] == expect
    assert p["from"]["version"] == steps[0][1] and p["to"]["version"] == steps[-1][2]


def test_removed_then_added_other_version():
    d = run(report(10, packages=[pc("removed", "a", frm="1.0")]),
            report(20, packages=[pc("added", "a", to="2.0")]))
    assert [p["change"] for p in d["packages"]] == ["changed"]


def test_same_package_at_two_sites_kept_apart():
    d = run(report(10, packages=[pc("added", "a", to="1", site="/x"),
                                 pc("added", "a", to="1", site="/y")]),
            report(20, packages=[pc("removed", "a", frm="1", site="/x")]))
    assert [(p["site"], p["change"]) for p in d["packages"]] == [("/y", "added")]
    assert [t["site"] for t in d["transient"]["packages"]] == ["/x"]


def test_source_change_is_not_transient():
    a = pc("changed", "a", "1.0", "1.0")
    a["to"]["direct_url"] = {"url": "git+https://x"}
    d = run(report(10, packages=[a]))
    assert [p["change"] for p in d["packages"]] == ["changed"]


# vulnerabilities, hooks, violations, origins, sites -----------------------------

def test_vuln_introduced_then_resolved_is_transient():
    d = run(report(10, "alert", new_vulns=[vuln("GHSA-1")]),
            report(20, resolved_vulns=[{"package": pkg("lodash", "1.1"), "id": "GHSA-1"}]))
    assert d["vulns"] == {"new": [], "resolved": []}
    [t] = d["transient"]["vulns"]
    assert t["id"] == "GHSA-1" and t["what"] == "fixed within the period"


def test_vuln_resolved_then_reintroduced_is_transient():
    d = run(report(10, resolved_vulns=[{"package": pkg("lodash", "1.0"), "id": "X"}]),
            report(20, "alert", new_vulns=[vuln("X")]))
    assert d["vulns"]["new"] == [] and d["transient"]["vulns"][0]["what"] == "resolved then reintroduced"


def test_vulns_net_new_sorted_with_first_source():
    d = run(report(10, "alert", new_vulns=[vuln("A", score=5.0, source="published"),
                                           vuln("B", score=9.8), vuln("C")]),
            report(20, "alert", new_vulns=[vuln("A", score=5.5, source="introduced")]),
            report(30, resolved_vulns=[{"package": pkg("x", "1"), "id": "Z"}] ))
    assert [v["id"] for v in d["vulns"]["new"]] == ["B", "A", "C"]
    a = d["vulns"]["new"][1]
    assert a["source"] == "published" and a["score"] == 5.5      # first source, latest details
    assert [v["id"] for v in d["vulns"]["resolved"]] == ["Z"]


def test_hook_added_then_removed_is_transient():
    d = run(report(10, "alert", hooks=[hook("added")]), report(20, hooks=[hook("removed")]))
    assert d["hooks"] == {"added": [], "removed": []}
    assert d["transient"]["hooks"][0]["hook"]["name"] == "postinstall"


def test_changed_hook_detail_is_a_new_hook():
    d = run(report(10, "alert", hooks=[hook("removed", detail="old"), hook("added", detail="new")]))
    assert [h["hook"]["detail"] for h in d["hooks"]["added"]] == ["new"]
    assert [h["hook"]["detail"] for h in d["hooks"]["removed"]] == ["old"]


def test_violations_net():
    v1 = {"ecosystem": "python", "package": "a", "dependency": None, "explain": "Unrequired", "sites": ["/s"]}
    v2 = v1 | {"package": "b"}
    d = run(report(10, "alert", new_violations=[v1, v2]), report(20, resolved_violations=[v1]))
    assert [v["package"] for v in d["violations"]["new"]] == ["b"]
    assert [v["package"] for v in d["transient"]["violations"]] == ["a"]


def test_origins_and_sites_net():
    o = {"change": "added", "ecosystem": "npm", "path": "/o"}
    s = {"change": "removed", "ecosystem": "npm", "kind": "lockfile", "path": "/s"}
    d = run(report(10, origins=[o], sites=[s]), report(20, origins=[o | {"change": "removed"}]))
    assert d["origins"]["added"] == [] and d["transient"]["origins"][0]["path"] == "/o"
    assert [x["path"] for x in d["sites"]["removed"]] == ["/s"]


# status, problems, window ---------------------------------------------------------

def test_alert_status_kept_after_cancellation():
    d = run(report(10, "alert", packages=[pc("downgraded", "a", "2", "1")]),
            report(20, "changed", packages=[pc("upgraded", "a", "1", "2")]))
    assert d["status"] == "alert" and d["packages"] == []
    assert d["alert_reports"] == [{"time": T0 + 10, "new_vulns": 0, "new_hooks": 0,
                                   "downgrades": 1, "new_violations": 0}]
    assert d["counts"]["downgrades"] == 0 and d["counts"]["eventful"]


def test_unchanged():
    d = run(start(0), scan(1), report(2, "unchanged"), period=300, window=(0, 300))
    assert d["status"] == "unchanged" and d["problems"] == []
    assert not d["counts"]["eventful"]


def test_problems():
    d = run(start(0, period=100), scan(1),
            report(5, "changed", audit_error="OSV timed out"),
            {"schema": 1, "event": "error", "time": T(6), "message": "Scan failed: x"},
            own("fetter-exit", now=T0 + 7, code=101, expected=False, restart_in=5).event,
            own("fetter-exit", now=T0 + 8, code=0, expected=True).event,
            own("stderr", now=T0 + 8, line="noise").event,
            own("supervisor-error", now=T0 + 9, message="not restarting").event,
            scan(400), window=(0, 500))
    # in time order; the expected exit and the stderr line are not problems
    assert [(p["kind"], p["time"] - T0) for p in d["problems"]] == [
        ("no-scan", 1), ("audit-error", 5), ("error", 6), ("fetter-exit", 7),
        ("supervisor-error", 9)]
    by = {p["kind"]: p for p in d["problems"]}
    assert "OSV timed out" in by["audit-error"]["message"]
    assert by["fetter-exit"]["message"] == "fetter exited with 101"
    gap = by["no-scan"]
    assert (gap["time"] - T0, gap["until"] - T0) == (1, 400)   # threshold 2 × 100 + 60
    assert [p["time"] for p in d["problems"]] == sorted(p["time"] for p in d["problems"])


def test_gaps_at_window_edges_and_none_without_period():
    d = run(scan(500), period=100, window=(0, 1000))
    assert [(p["time"] - T0, p["until"] - T0) for p in d["problems"]] == [(0, 500), (500, 1000)]
    assert run(scan(500), window=(0, 1000))["problems"] == []


def test_period_from_start_event():
    d = run(start(0, period=10), scan(1), scan(200), window=(0, 210))
    assert [p["kind"] for p in d["problems"]] == ["no-scan"]


def test_window_excludes_outside_entries():
    d = run(report(5, "alert", new_vulns=[vuln("A")]), report(50, new_vulns=[vuln("B")]),
            window=(10, 100))
    assert [v["id"] for v in d["vulns"]["new"]] == ["B"] and d["status"] == "changed"
    assert d["reports"] == 1


# fixed baseline ------------------------------------------------------------------

def test_fixed_baseline_uses_last_report():
    d = run(start(0, baseline="/base.json"),
            report(10, "alert", packages=[pc("added", "a", to="1")], new_vulns=[vuln("X")]),
            report(20, "changed", packages=[pc("added", "a", to="1"), pc("upgraded", "b", "1", "2")]),
            report(30, "changed", packages=[pc("upgraded", "b", "1", "3")]))
    assert d["baseline"] == "/base.json"
    assert [(p["key"], p["change"], p["to"]["version"]) for p in d["packages"]] == [("b", "upgraded", "3")]
    [a] = d["transient"]["packages"]
    assert a["key"] == "a" and a["what"] == "added, then back to the baseline"
    assert (a["first"], a["last"]) == (T0 + 10, T0 + 20)
    assert [v["id"] for v in d["transient"]["vulns"]] == ["X"]
    assert d["status"] == "alert"


def test_fixed_baseline_from_config():
    d = run(report(10, packages=[pc("added", "a", to="1")]), report(20), baseline="/b.json")
    assert d["packages"] == [] and d["transient"]["packages"][0]["key"] == "a"


# fixtures -----------------------------------------------------------------------

def test_fold_recorded_streams():
    entries = [parse_line(x).event for f in ("quiet", "changes")
               for x in (STREAMS / f"{f}.jsonl").read_text().splitlines()]
    t0 = entries[0]["time"]["secs"]
    d = fold(entries, t0 - 1, t0 + 60, period=600)
    assert d["status"] == "alert" and d["reports"] == 3 and d["starts"] == 2
    assert [(p["key"], p["change"]) for p in d["packages"]] == [("left-pad", "added"),
                                                               ("lodash", "downgraded")]
    scores = [v.get("score") or 0 for v in d["vulns"]["new"]]
    assert scores == sorted(scores, reverse=True) and len(scores) == 5
    assert {v["source"] for v in d["vulns"]["new"]} == {"existing", "introduced"}
    assert [p["kind"] for p in d["problems"]] == ["error"]
    assert d["system"]["hostname"] == "host"
    assert d["counts"]["downgrades"] == 1 and d["counts"]["changes"] == 2


def test_pending_window():
    assert pending_window({}, 100.0, 500.0) == (100.0, 500.0)
    assert pending_window({"digest": {"last_end": 300.0}}, 100.0, 500.0) == (300.0, 500.0)
    assert pending_window({}, None, 500.0) == (500.0, 500.0)
    assert pending_window({"digest": "bad"}, 100.0, 500.0) == (100.0, 500.0)
