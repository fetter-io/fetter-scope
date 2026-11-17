import time
from pathlib import Path

from textual.widgets import DataTable, Input, Static

from fetter_scope.model import Model
from fetter_scope.store import Store
from fetter_scope.supervisor import Runtime
from fetter_scope.tui import AlertDetail, ScopeApp

from tests.test_model import loaded, scan
from tests.test_supervisor import FAST, cmd

STREAMS = Path(__file__).parent / "fixtures" / "streams"
SIZE = (160, 45)


def rows(app, tab: str) -> list[list[str]]:
    t = app.query_one(f"#{tab}-table", DataTable)
    return [[str(c) for c in t.get_row_at(i)] for i in range(t.row_count)]


def text(app, selector: str) -> str:
    return str(app.query_one(selector, Static).render())


async def until(pilot, pred, timeout=10):
    deadline = time.monotonic() + timeout
    while not pred():
        assert time.monotonic() < deadline, "timed out"
        await pilot.pause(0.05)


async def show(pilot, key):
    await pilot.press(key)
    await pilot.pause(0.1)


async def test_tabs_fill_from_model():
    app = ScopeApp(loaded("quiet", "changes", attached=True))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.1)
        header = text(app, "#header")
        assert "fetter · host (linux 24.04 x86_64)" in header
        assert "ALERT" in header and "attached: read-only" in header
        assert "Latest report" in text(app, "#ov-report")
        assert "Pending digest since" in text(app, "#ov-digest")
        assert app.query_one("#ecosystems", DataTable).row_count == 1
        await show(pilot, "2")
        alerts = rows(app, "alerts")
        assert len(alerts) == 6 and alerts[0][0] == "downgrade"   # newest first
        await show(pilot, "3")
        assert [r[0] for r in rows(app, "changes")] == ["downgraded", "added"]
        assert "since the last report, folded" in text(app, "#changes-mode")
        await show(pilot, "4")
        assert len(rows(app, "live")) == 2
        await show(pilot, "9")
        log = rows(app, "log")
        assert len(log) == 11 and log[-1][1] == "error"


async def test_filter_and_toggle():
    app = ScopeApp(loaded("quiet", "changes", attached=True))
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "3")
        await show(pilot, "t")
        assert "since the last report, every report" in text(app, "#changes-mode")
        await show(pilot, "slash")
        box = app.query_one("#filter", Input)
        assert box.has_focus and not box.disabled
        await pilot.press(*"kind:down")
        await pilot.pause(0.1)
        assert [r[3] for r in rows(app, "changes")] == ["lodash"]
        await show(pilot, "enter")                     # back to the table, filter kept
        assert app.query_one("#changes-table").has_focus
        await show(pilot, "2")                          # other tabs are unfiltered
        assert len(rows(app, "alerts")) == 6 and app.query_one("#filter").disabled
        await show(pilot, "3")
        assert len(rows(app, "changes")) == 1 and box.value == "kind:down"
        await show(pilot, "slash")
        await show(pilot, "escape")
        assert len(rows(app, "changes")) == 2 and box.disabled


async def test_alert_detail():
    app = ScopeApp(loaded("quiet", "changes", attached=True))
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "2")
        table = app.query_one("#alerts-table", DataTable)
        table.move_cursor(row=next(i for i, r in enumerate(rows(app, "alerts"))
                                   if r[4].startswith("GHSA-p6mc")))
        await show(pilot, "enter")
        assert isinstance(app.screen, AlertDetail)
        detail = str(app.screen.query_one("#detail", Static).render())
        assert "GHSA-p6mc-m468-83gw" in detail and "https://osv.dev/vulnerability/" in detail
        assert "introduced (the package was added or changed)" in detail
        assert "/home/user/proj/package-lock.json" in detail      # from the package changes
        await show(pilot, "escape")
        assert not isinstance(app.screen, AlertDetail)


async def test_overview_flags_ecosystem_dropped_to_zero():
    m = Model(attached=True)
    m.add(scan(1, {"npm": {"origins": 1, "sites": 1, "packages": 3}}))
    m.add(scan(2, {"npm": {"origins": 1, "sites": 1, "packages": 0}}))
    app = ScopeApp(m)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.1)
        assert "npm dropped to zero packages" in text(app, "#ov-report")
        assert app.query_one("#spark").data == [3, 0]


async def test_attach_follows_appended_file(tmp_path):
    f = tmp_path / "stream.jsonl"
    lines = (STREAMS / "changes.jsonl").read_text().splitlines()
    f.write_text("\n".join(lines[:2]) + "\n")
    app = ScopeApp(Model(attached=True), follow_path=f)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: len(app.model.log) == 2)
        with open(f, "a") as fh:
            fh.write("\n".join(lines[2:]) + "\n")
        await until(pilot, lambda: len(app.model.log) == 6)
        await show(pilot, "2")
        await until(pilot, lambda: len(rows(app, "alerts")) == 4)
        await pilot.press("q")


async def test_launch_mode_runs_and_quits_cleanly(home):
    store = Store(home)
    runtime = Runtime(cmd(), store, out=None, timing=FAST, signals=False)
    app = ScopeApp(Model(), runtime=runtime, store=store, fetter_version="5.1.0")
    runtime.tap = app.ingest
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.model.fetter == "running" and app.model.scans)
        await pilot.pause(0.6)
        assert "fetter 5.1.0" in text(app, "#header") and "next scan" in text(app, "#header")
        await pilot.press("q")
        await until(pilot, lambda: runtime.supervisor.status == "stopped")
    kinds = [p.kind for p in store.iter_entries()]
    assert kinds == ["launch", "start", "scan", "control", "fetter-exit"]
    assert list(store.iter_entries())[-1].event["expected"]


async def test_launch_mode_shows_fetter_failure(home, tmp_path):
    store = Store(home)
    runtime = Runtime(cmd("--fake-fail-first", "99"), store, out=None, timing=FAST, signals=False)
    app = ScopeApp(Model(), runtime=runtime, store=store)
    runtime.tap = app.ingest
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.model.fetter == "failed")
        await pilot.pause(0.6)
        assert "fetter failed" in text(app, "#header")
        await show(pilot, "9")
        assert any(r[1] == "supervisor-error" for r in rows(app, "log"))
        await pilot.press("q")


def test_alert_detail_sites_from_finding():
    import json
    from fetter_scope.events import parse_line
    from fetter_scope.tui import alert_detail
    from tests.test_digest import report, vuln
    m = Model(attached=True)
    m.add(parse_line(json.dumps(report(1, "alert", new_vulns=[
        vuln("A", source="published") | {"sites": ["/x/node_modules", "/y/node_modules"]},
        vuln("B", key="other")]))))
    a, b = m.alerts
    assert a.site == "/x/node_modules, /y/node_modules"
    detail = str(alert_detail(a, m))
    assert "/x/node_modules" in detail and "/y/node_modules" in detail and "not in the stream" not in detail
    assert "not in the stream" in str(alert_detail(b, m))     # fetter before 5.1.0: no sites, no changes


async def test_sites_tab_and_detail():
    import json
    from fetter_scope.events import parse_line
    from tests.test_digest import report, vuln
    m = Model(attached=True)
    m.add(parse_line(json.dumps(report(1, "alert", new_vulns=[
        vuln("GHSA-hi", score=9.8) | {"sites": ["/proj/node_modules"]},
        vuln("GHSA-lo", key="x", score=4.0) | {"sites": ["/proj/node_modules", "/other/node_modules"]},
    ]))))
    app = ScopeApp(m)
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "6")
        assert app.active_tab == "sites"
        got = rows(app, "sites")
        assert [(r[0], r[1], r[2], r[3], r[8]) for r in got] == [
            ("9.8", "6.9", "2", "1", "/proj/node_modules"), ("4", "4", "1", "", "/other/node_modules")]
        assert "1 site" not in text(app, "#sites-mode") and "2 sites with open" in text(app, "#sites-mode")
        await show(pilot, "slash")
        await pilot.press(*"other")
        await pilot.pause(0.1)
        assert [r[8] for r in rows(app, "sites")] == ["/other/node_modules"]
        await show(pilot, "escape")
        app.query_one("#sites-table", DataTable).move_cursor(row=0)
        await show(pilot, "enter")
        detail = str(app.screen.query_one("#detail", Static).render())
        assert "/proj/node_modules" in detail and "GHSA-hi" in detail and "max 9.8, median 6.9" in detail
        assert detail.index("GHSA-hi") < detail.index("GHSA-lo")
