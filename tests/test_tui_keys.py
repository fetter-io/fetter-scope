import json
import time
from pathlib import Path

from rich.text import Text
from textual.widgets import DataTable, Static

from fetter_scope import config, tui
from fetter_scope.events import parse_line
from fetter_scope.model import Model
from fetter_scope.scheduler import Mailer
from fetter_scope.store import Store
from fetter_scope.supervisor import Runtime
from fetter_scope.tui import ALL, Detail, EcoBar, ScopeApp, next_sort, ordered

from tests.test_digest import T0, hook, pc, report, vuln
from tests.test_model import loaded
from tests.test_scheduler import ENV, Sender
from tests.test_supervisor import FAST, cmd
from tests.test_tui import SIZE, rows, show, text, until


# sorting ---------------------------------------------------------------------------

def test_ordered_and_next_sort():
    rs = [("a", ["x", Text("2")], [None, 2.0]), ("b", ["y", ""], None),
          ("c", ["Z", Text("10")], [None, 10.0]), ("d", ["w", "—"], None)]
    assert [k for k, _, _ in ordered(rs, (1, False))] == ["a", "c", "b", "d"]   # empty last
    assert [k for k, _, _ in ordered(rs, (1, True))] == ["c", "a", "b", "d"]
    assert [k for k, _, _ in ordered(rs, (0, False))] == ["d", "a", "b", "c"]   # case-insensitive
    assert ordered(rs, None) is rs
    assert next_sort(None, 2) == (2, False)
    assert next_sort((2, False), 2) == (2, True)
    assert next_sort((2, True), 2) is None
    assert next_sort((2, True), 3) == (3, False)


def entries_with_hooks():
    t = int(time.time()) - 600
    out = []
    for i, r in enumerate([
        report(0, "alert", new_vulns=[vuln("GHSA-low", score=2.0), vuln("GHSA-high", score=9.1)],
               hooks=[hook("added", "evil.pth", "import os\nos.system('x')")]),
        report(0, "changed", resolved_vulns=[{"package": {"ecosystem": "npm", "key": "q",
                                                          "name": "q", "version": "1"},
                                              "id": "GHSA-gone"}],
               hooks=[hook("removed", "old.pth", "import old")]),
    ]):
        r = dict(r, time={"secs": t + i, "nanos": 0}, system={"hostname": "host"})
        r["report"] = dict(r["report"], time=r["time"])
        out.append(parse_line(json.dumps(r)))
    return out


def model_with_hooks() -> Model:
    m = Model(attached=True)
    for p in entries_with_hooks():
        m.add(p)
    return m


async def test_vulns_tab_sorted_by_cvss_and_header_click():
    app = ScopeApp(model_with_hooks())
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "5")
        assert [(r[0], r[1], r[2]) for r in rows(app, "vulns")] == [
            ("GHSA-high", "9.1", "new"), ("GHSA-low", "2", "new"), ("GHSA-gone", "", "resolved")]
        table = app.query_one("#vulns-table", DataTable)
        assert str(table.columns["CVSS"].label) == "CVSS ▼"
        id_col = list(table.columns).index("ID")
        for expect in (["GHSA-gone", "GHSA-high", "GHSA-low"], ["GHSA-low", "GHSA-high", "GHSA-gone"]):
            app.post_message(DataTable.HeaderSelected(table, "ID", id_col, Text("ID")))
            await pilot.pause(0.1)
            assert [r[0] for r in rows(app, "vulns")] == expect
        assert str(table.columns["ID"].label) == "ID ▼"


async def test_hooks_tab_and_detail():
    app = ScopeApp(model_with_hooks())
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "7")
        assert [(r[0], r[3], r[4]) for r in rows(app, "hooks")] == [
            ("added", "evil.pth", "import os"), ("removed", "old.pth", "import old")]
        await show(pilot, "enter")
        assert isinstance(app.screen, Detail)
        detail = str(app.screen.query_one("#detail", Static).render())
        assert "os.system('x')" in detail and "never run" in detail and "added" in detail


async def test_copy(monkeypatch):
    copied, tools = [], []
    monkeypatch.setattr(tui, "system_copy", lambda t: tools.append(t) or "xclip")
    app = ScopeApp(model_with_hooks())
    async with app.run_test(size=SIZE) as pilot:
        app.copy_to_clipboard = copied.append
        await show(pilot, "5")
        await show(pilot, "c")
        await show(pilot, "u")
        assert copied == ["GHSA-high", "https://osv.dev/GHSA-high"] == tools
        await show(pilot, "enter")                      # in the detail too
        await show(pilot, "u")
        assert copied[-1] == "https://osv.dev/GHSA-high"
        await show(pilot, "escape")
        n = len(copied)
        await show(pilot, "3")                          # no package changes: nothing to copy
        await show(pilot, "c")
        assert len(copied) == n
        await show(pilot, "2")                          # the newest alert: the hook
        await show(pilot, "c")
        assert copied[-1] == "evil.pth"


async def test_attach_mode_refuses_control_and_mail(monkeypatch):
    app = ScopeApp(loaded("changes", attached=True))
    notes = []
    async with app.run_test(size=SIZE) as pilot:
        app.notify = lambda msg, **kw: notes.append(msg)
        for key in ("s", "r", "m", "l"):
            await show(pilot, key)
    assert notes == ["attached: read-only, no control channel"] * 2 + [
        "attached: mail is sent by the fetter-scope running fetter", "nothing to reload when attached"]


async def test_preview_opens_html(monkeypatch):
    opened = []
    monkeypatch.setattr(tui, "open_browser", opened.append)
    app = ScopeApp(loaded("changes", attached=True))
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "p")
    path = Path(opened[0].removeprefix("file://"))
    try:
        assert "<!doctype html>" in path.read_text() and "Downgrades" in path.read_text()
    finally:
        path.unlink()


# launch mode ------------------------------------------------------------------------

def launched(home, *flags, mailer_env=None, toml=""):
    home.root.mkdir(parents=True, exist_ok=True)
    home.config.write_text("[mail]\nenabled = true\n" + toml)
    cfg = config.load(home, environ=ENV if mailer_env is None else mailer_env)
    store, sender = Store(home), Sender()
    mailer = Mailer(cfg, store, send=sender)
    runtime = Runtime(cmd(*flags), store, out=None, timing=FAST, signals=False, mailer=mailer)
    app = ScopeApp(Model(), runtime=runtime, store=store, mailer=mailer, fetter_version="5.1.0",
                   load_config=lambda: config.load(home, environ=ENV))
    runtime.tap = app.ingest
    return app, store, sender


async def test_rescan_and_report_keys(home):
    app, store, _ = launched(home, "--fake-delay", "1.5")
    notes = []
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.model.scans)
        app.notify = lambda msg, **kw: notes.append(msg)
        await show(pilot, "s")
        await pilot.pause(0.5)                          # the header refreshes on a timer
        assert "rescanning…" in text(app, "#header")
        await show(pilot, "s")                          # ignored while outstanding
        await until(pilot, lambda: len(app.model.scans) == 2)
        await show(pilot, "r")
        await until(pilot, lambda: len(app.model.reports) == 1)
        await pilot.press("q")
        await until(pilot, lambda: app.runtime.supervisor.status == "stopped")
    sent = [p.event["command"] for p in store.iter_entries() if p.kind == "control"]
    assert sent == ["scan", "report", "stop"]
    assert notes == ["scan requested; waiting for fetter",
                     "stopping fetter… (q again to terminate it)"]


async def test_mail_key_reports_then_sends(home):
    app, store, sender = launched(home)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.model.scans)
        await show(pilot, "m")
        await until(pilot, lambda: sender.messages)
        await show(pilot, "8")
        await until(pilot, lambda: "sent" in [r[2] for r in rows(app, "mail")])
        info = text(app, "#mail-info")
        assert "postmark" in info and "a@x.org" in info and "sent" in info
        # the next period's preview: quiet so far, but still about this host
        assert "Subject: fetter host · " in str(app.query_one("#mail-preview", Static).render())
        await pilot.press("q")
        await until(pilot, lambda: app.runtime.supervisor.status == "stopped")
    kinds = [p.kind for p in store.iter_entries()]
    assert kinds.index("report") < kinds.index("mail")       # a fresh report went first
    assert sender.subjects() == ["fetter host · changed"]


async def test_mail_key_not_configured(home):
    app, store, sender = launched(home, mailer_env={})
    notes = []
    async with app.run_test(size=SIZE) as pilot:
        app.notify = lambda msg, **kw: notes.append(msg)
        await show(pilot, "m")
        await pilot.press("q")
    assert notes[0].startswith("mail not configured: REPORT_EMAIL_FROM")
    assert sender.messages == []


async def test_reload_mail_settings(home):
    app, store, sender = launched(home)
    notes = []
    async with app.run_test(size=SIZE) as pilot:
        app.notify = lambda msg, **kw: notes.append(msg)
        home.config.write_text('[mail]\nenabled = true\nevery = "6h"\n[fetter]\nperiod = 60\n')
        await show(pilot, "l")
        assert app.mailer.cfg.mail.every == 6 * 3600 and app.mailer.cfg.fetter.period == 300
        home.config.write_text("[mail]\nevery = \"x\"\n")
        await show(pilot, "l")
        assert app.mailer.cfg.mail.every == 6 * 3600
        await pilot.press("q")
    assert notes[:2] == ["reloaded mail settings",
                         "fetter settings changed: restart fetter-scope to apply them"]
    assert notes[2].startswith("config.toml has errors; settings kept")


async def test_duplicate_alert_fields_do_not_crash():
    m = Model(attached=True)
    m.add(parse_line(json.dumps(report(0, "alert", new_vulns=[
        vuln("GHSA-same", version="4.17.21"), vuln("GHSA-same", version="4.17.15")]))))
    app = ScopeApp(m)
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "2")
        assert [r[2] for r in rows(app, "alerts")] == ["lodash 4.17.15", "lodash 4.17.21"]
        await show(pilot, "down")
        await show(pilot, "enter")
        assert "lodash 4.17.21" in str(app.screen.query_one("#detail", Static).render())


async def test_fill_makes_repeated_keys_unique():
    from textual.app import App
    from fetter_scope.tui import fill

    class One(App):
        def compose(self):
            yield DataTable()

    app = One()
    async with app.run_test():
        table = app.query_one(DataTable)
        fill(table, ["A"], [("k", ["x"], None), ("k", ["y"], None), ("k", ["z"], None)])
        assert [str(k.value) for k in table.rows] == ["k", "k#2", "k#3"]


def two_ecosystems() -> Model:
    """Alerts and changes in npm and python (the fixture streams are npm only)."""
    def py(d: dict) -> dict:
        for p in [d.get("package"), d.get("from"), d.get("to")]:
            if p:
                p["ecosystem"] = "python"
        return d | ({"ecosystem": "python"} if "change" in d else {})
    m = Model(attached=True)
    m.add(parse_line(json.dumps(report(
        10, status="alert",
        packages=[pc("added", "left-pad", to="1.3.0"), py(pc("added", "requests", to="2.19.0")),
                  py(pc("added", "urllib3", to="1.21"))],
        new_vulns=[vuln("GHSA-npm", score=7.5), py(vuln("PYSEC-1", key="requests", score=9.8)),
                   py(vuln("PYSEC-2", key="urllib3"))]))))
    return m


async def test_ecosystem_selector_is_global():
    app = ScopeApp(two_ecosystems(), now=lambda: T0 + 100)
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "2")
        assert sorted(r[1] for r in rows(app, "alerts")) == ["npm", "python", "python"]
        bar = app.query_one("#alerts-ecos", EcoBar)
        assert bar.names == [ALL, "npm", "python"]
        assert [str(b.label) for b in bar.boxes()] == ["all", "npm 1", "python 2"]
        await show(pilot, "e")                           # focuses npm (the first after "all")
        assert bar.boxes()[1].has_focus
        await show(pilot, "space")                       # npm off
        assert app.hidden_ecos == {"npm"}
        assert [r[1] for r in rows(app, "alerts")] == ["python", "python"]
        assert [b.value for b in bar.boxes()] == [False, False, True]
        assert [b.BUTTON_INNER.strip() for b in bar.boxes()] == ["○", "○", "●"]
        await show(pilot, "3")                           # the same selection on other tabs
        assert {r[1] for r in rows(app, "changes")} == {"python"}
        changes_bar = app.query_one("#changes-ecos", EcoBar)
        assert [b.value for b in changes_bar.boxes()] == [False, False, True]
        await show(pilot, "5")
        assert {r[3] for r in rows(app, "vulns")} == {"python"}
        await show(pilot, "e")
        await show(pilot, "right")                       # python
        await show(pilot, "o")                           # only python: no change here
        assert app.hidden_ecos == {"npm"}
        await show(pilot, "left")
        await show(pilot, "o")                           # only npm
        assert app.hidden_ecos == {"python"}
        assert {r[3] for r in rows(app, "vulns")} == {"npm"}
        await show(pilot, "left")
        await show(pilot, "space")                       # "all" on
        assert app.hidden_ecos == set() and len(rows(app, "vulns")) == 3
        await show(pilot, "down")                        # back to the table
        assert app.query_one("#vulns-table").has_focus


async def test_ecosystem_selector_counts_follow_text_filter_and_skip_other_tabs():
    app = ScopeApp(two_ecosystems(), now=lambda: T0 + 100)
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "2")
        await show(pilot, "slash")
        await pilot.press(*"type:vuln")
        await pilot.pause(0.1)
        bar = app.query_one("#alerts-ecos", EcoBar)
        assert [str(b.label) for b in bar.boxes()][1:] == ["npm 1", "python 2"]
        await pilot.press("escape")
        await show(pilot, "6")                           # Sites has no selector
        assert not app.query("#sites-ecos")
        await show(pilot, "e")
        assert app.focused is None or not isinstance(app.focused.parent, EcoBar)


async def test_ecosystem_selector_at_the_same_height_on_every_tab():
    """Each tab with the selector has a one-row status line above it, so it does not move."""
    for size in (SIZE, (80, 30)):                   # narrow: long status lines are cut, not wrapped
        app = ScopeApp(two_ecosystems(), now=lambda: T0 + 100)
        async with app.run_test(size=size) as pilot:
            ys = {}
            for key, tab in (("2", "alerts"), ("3", "changes"), ("4", "live"), ("5", "vulns"),
                             ("7", "hooks")):
                await show(pilot, key)
                ys[tab] = app.query_one(f"#{tab}-ecos", EcoBar).region.y
                assert app.query_one(f"#{tab}-mode", Static).region.height == 1
            assert len(set(ys.values())) == 1, ys
            assert "1 report" in text(app, "#alerts-mode")


async def test_changes_and_live_status_name_what_they_compare_with():
    app = ScopeApp(loaded("quiet", "changes", attached=True), baseline="/b.json")
    async with app.run_test(size=SIZE) as pilot:
        await show(pilot, "4")
        assert text(app, "#live-mode").startswith("Changes since the previous scan")
        await show(pilot, "3")
        assert "since the last report" in text(app, "#changes-mode")   # the stream's start: rolling
        app.model.start = dict(app.model.start, baseline="/b.json")
        app.refresh_views(force=True)
        await pilot.pause(0.1)
        assert text(app, "#changes-mode").startswith("Package changes since the baseline")
