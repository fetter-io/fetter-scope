import asyncio
import json
import time
from datetime import datetime

import pytest

from fetter_scope import config, delivery
from fetter_scope.__main__ import main
from fetter_scope.config import MailConfig
from fetter_scope.events import parse_line
from fetter_scope.scheduler import Mailer, backoff, next_boundary
from fetter_scope.store import Store

from tests.test_digest import hook, pc, report, scan, vuln

ENV = {"REPORT_EMAIL_FROM": "s@x.org", "REPORT_EMAIL_TO": "a@x.org", "POSTMARK_SERVER_TOKEN": "t"}


@pytest.fixture(autouse=True)
def utc(monkeypatch):
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def ts(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def iso(t: float) -> str:
    return datetime.fromtimestamp(t).isoformat(timespec="minutes")


# timing --------------------------------------------------------------------------

def mail(**kw) -> MailConfig:
    return MailConfig(**kw)


@pytest.mark.parametrize("cfg,after,expect", [
    (mail(), "2027-01-15T06:00", "2027-01-15T07:00"),
    (mail(), "2027-01-15T07:00", "2027-01-16T07:00"),          # strictly after
    (mail(at=(23, 30)), "2027-01-15T23:45", "2027-01-16T23:30"),
    (mail(every=6 * 3600), "2027-01-15T07:00", "2027-01-15T13:00"),
    (mail(every=6 * 3600), "2027-01-15T00:30", "2027-01-15T01:00"),
    (mail(every=7 * 86400, weekday="mon"), "2027-01-15T12:00", "2027-01-18T07:00"),  # Fri → Mon
    (mail(every=7 * 86400, weekday="fri", at=(9, 0)), "2027-01-15T08:00", "2027-01-15T09:00"),
    (mail(every=7 * 86400), "2027-01-15T12:00", "2027-01-18T07:00"),   # weekly from Monday
])
def test_next_boundary(cfg, after, expect):
    assert iso(next_boundary(ts(after), cfg)) == expect


def test_two_day_schedule_is_stable():
    cfg = mail(every=2 * 86400)
    a = next_boundary(ts("2027-01-15T12:00"), cfg)
    b = next_boundary(a, cfg)
    assert b - a == 2 * 86400
    assert next_boundary(ts("2027-01-15T12:00") + 3600, cfg) == a    # same grid


def test_daily_boundary_keeps_wall_clock_over_dst(monkeypatch):
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    t = next_boundary(datetime(2027, 3, 13, 8, 0).timestamp(), mail())   # DST starts 03-14
    assert datetime.fromtimestamp(t) == datetime(2027, 3, 14, 7, 0)
    assert t - datetime(2027, 3, 13, 7, 0).timestamp() == 23 * 3600


def test_backoff():
    assert [backoff(n) for n in (1, 2, 3, 6, 7, 20)] == [60, 120, 240, 1920, 3600, 3600]


# Mailer ---------------------------------------------------------------------------

class Clock:
    def __init__(self, t: str):
        self.t = ts(t)

    def __call__(self) -> float:
        return self.t

    def at(self, s: str) -> None:
        self.t = ts(s)

    def add(self, seconds: float) -> None:
        self.t += seconds


class Sender:
    def __init__(self):
        self.messages, self.fail = [], False

    def __call__(self, m, transport, creds, transports):
        self.messages.append(m)
        if self.fail:
            return delivery.Result("failed", "HTTP 500")
        return delivery.Result("sent")

    def subjects(self):
        return [m.subject for m in self.messages]


def setup(home, toml="", env=ENV, start="2027-01-15T06:00"):
    home.root.mkdir(parents=True, exist_ok=True)
    # a long scan period: these logs have no scans, and missing scans are tested elsewhere
    home.config.write_text("[fetter]\nperiod = 1000000\n[mail]\nenabled = true\n" + toml)
    cfg = config.load(home, environ=env)
    assert cfg.errors == ()
    clock = Clock(start)
    store = Store(home, now=clock)
    sender, emitted = Sender(), []
    m = Mailer(cfg, store, now=clock, send=sender, emit=emitted.append)
    m.start()
    return m, store, clock, sender, emitted


def log(store, clock, *events):
    """Append events at the clock's time (their own times are set to it)."""
    for e in events:
        e = dict(e, system={"hostname": "host"})
        e["time"] = {"secs": int(clock.t), "nanos": 0}
        if "report" in e:
            e["report"] = dict(e["report"], time=e["time"])
        store.append(parse_line(json.dumps(e)))


def alert_report(*vulns_, hooks=()):
    return report(0, "alert", new_vulns=list(vulns_), hooks=list(hooks))


async def test_digest_at_boundary(home):
    m, store, clock, sender, emitted = setup(home)
    log(store, clock, report(0, "changed", packages=[pc("added", "a", to="1")]))
    clock.at("2027-01-15T06:59")
    assert await m.tick() == [] and sender.messages == []
    clock.at("2027-01-15T07:00")
    [r] = await m.tick()
    assert r.ok
    [msg] = sender.messages
    assert msg.subject == "fetter host · 1 change"
    [att] = msg.attachments
    assert json.loads(att.content)["packages"][0]["key"] == "a"
    state = store.read_state()
    # the next period starts just after the last entry included
    assert state["digest"]["last_end"] == ts("2027-01-15T06:00") + 1e-6
    assert state["digest"]["last_at"] == clock.t and state["digest"]["last_result"] == "sent"
    assert [h["kind"] for h in state["mail_history"]] == ["digest"]
    files = sorted(p.name for p in home.mail.iterdir())
    assert files == ["2027-01-15T0700.html", "2027-01-15T0700.json", "2027-01-15T0700.txt"]
    assert emitted[-1].kind == "mail" and emitted[-1].event["result"] == "sent"
    assert m.next_digest_at() == ts("2027-01-16T07:00")
    clock.at("2027-01-15T08:00")
    assert await m.tick() == []


async def test_unchanged_not_sent_but_period_advances(home):
    m, store, clock, sender, _ = setup(home)
    log(store, clock, scan(0), report(0, "unchanged"))
    clock.at("2027-01-15T07:00")
    assert await m.tick() == [] and sender.messages == []
    dg = store.read_state()["digest"]
    assert dg["last_at"] == clock.t and dg["last_result"] == "unchanged, not sent"


async def test_send_unchanged(home):
    m, store, clock, sender, _ = setup(home, "send_unchanged = true\n")
    log(store, clock, scan(0))
    clock.at("2027-01-15T07:00")
    await m.tick()
    assert sender.subjects() == ["fetter host · unchanged"]


async def test_catch_up_after_downtime(home):
    m, store, clock, sender, _ = setup(home, start="2027-01-12T06:00")
    log(store, clock, report(0, "changed", packages=[pc("added", "old", to="1")]))
    clock.at("2027-01-15T10:30")                    # missed three boundaries
    assert len(await m.tick()) == 1
    d = json.loads(sender.messages[0].attachments[0].content)
    assert (d["start"], d["end"]) == (ts("2027-01-12T06:00"), ts("2027-01-15T10:30"))
    assert m.next_digest_at() == ts("2027-01-16T07:00")


async def test_failure_keeps_period_and_backs_off(home):
    m, store, clock, sender, emitted = setup(home)
    log(store, clock, report(0, "changed", packages=[pc("added", "a", to="1")]))
    sender.fail = True
    clock.at("2027-01-15T07:00")
    [r] = await m.tick()
    assert r.status == "failed"
    dg = store.read_state()["digest"]
    assert dg["last_end"] == ts("2027-01-15T06:00") and dg["failures"] == 1
    assert m.next_digest_at() == ts("2027-01-15T07:01") and "failing" in m.status()
    clock.add(30)
    assert await m.tick() == []
    clock.add(31)
    [r] = await m.tick()                             # second failure: 2 minutes
    assert m.next_digest_at() == clock.t + 120
    sender.fail = False
    clock.add(120)
    [r] = await m.tick()
    assert r.ok and len(sender.messages) == 3
    dg = store.read_state()["digest"]
    assert dg["failures"] == 0 and dg["last_at"] == clock.t and m.status() == "mail ok"
    assert emitted[0].event["result"] == "failed"
    assert not list(home.mail.glob("*T0700*"))       # only the sent one was saved


async def test_immediate_alert_rate_limited_and_marked_in_digest(home):
    m, store, clock, sender, _ = setup(home, 'alert_min_interval = "15m"\n')
    clock.at("2027-01-15T06:10")
    log(store, clock, alert_report(vuln("GHSA-1", score=9.0)))
    assert m.on_entry(next(iter(store.iter_entries(since=clock.t))))
    [r] = await m.tick()
    assert r.ok and sender.subjects() == ["fetter host · ALERT · 1 new vuln"]
    assert "New vulnerabilities" in sender.messages[0].text
    assert "Changes" not in sender.messages[0].text and not sender.messages[0].attachments

    clock.at("2027-01-15T06:15")                     # within 15 minutes: waits
    log(store, clock, alert_report(hooks=[hook("added")]))
    m.on_entry(list(store.iter_entries(since=clock.t))[-1])
    assert await m.tick() == []
    assert m.next_alert_at() == ts("2027-01-15T06:25")
    clock.at("2027-01-15T06:25")
    [r] = await m.tick()
    assert sender.subjects()[-1] == "fetter host · ALERT · 1 hook"   # only what is new

    clock.at("2027-01-15T06:40")
    log(store, clock, report(0, "changed", new_vulns=[vuln("GHSA-2", score=1.0)]))
    clock.at("2027-01-15T07:00")
    await m.tick()
    d = json.loads(sender.messages[-1].attachments[0].content)
    assert {v["id"]: v["mailed"] for v in d["vulns"]["new"]} == {"GHSA-1": True, "GHSA-2": False}
    assert d["hooks"]["added"][0]["mailed"] is True
    assert "mailed" in sender.messages[-1].text
    assert store.read_state()["alerts"]["windows"] == []          # pruned by the digest
    assert sorted(p.name for p in home.mail.glob("*-alert.json")) == \
        ["2027-01-15T0610-alert.json", "2027-01-15T0625-alert.json"]


async def test_alert_failure_retries(home):
    m, store, clock, sender, _ = setup(home)
    clock.add(5)
    log(store, clock, alert_report(vuln("X")))
    m.on_entry(list(store.iter_entries())[-1])
    sender.fail = True
    [r] = await m.tick()
    assert not r.ok and m.next_alert_at() == clock.t + 60
    sender.fail = False
    clock.add(60)
    [r] = await m.tick()
    assert r.ok and sender.subjects()[-1].startswith("fetter host · ALERT · 1 new vuln")


async def test_alerts_digest_mode_sends_no_alert_mail(home):
    m, store, clock, sender, _ = setup(home, 'alerts = "digest"\n')
    log(store, clock, alert_report(vuln("X")))
    assert not m.on_entry(list(store.iter_entries())[-1])
    assert await m.tick() == []


async def test_not_configured_and_disabled(home):
    m, store, clock, sender, _ = setup(home, env={})
    log(store, clock, alert_report(vuln("X")))
    m.on_entry(list(store.iter_entries())[-1])
    clock.at("2027-01-16T07:00")
    assert await m.tick() == [] and sender.messages == []
    assert m.status().startswith("mail not configured (REPORT_EMAIL_FROM")

    home.config.write_text("[mail]\nenabled = false\n")
    m2 = Mailer(config.load(home, environ=ENV), store, now=clock, send=sender)
    assert m2.status() == "mail disabled" and await m2.tick() == []


async def test_failed_mail_is_a_digest_problem(home):
    m, store, clock, sender, emitted = setup(home)
    m.emit = lambda p: (emitted.append(p), store.append(p))
    log(store, clock, report(0, "changed", packages=[pc("added", "a", to="1")]))
    sender.fail = True
    clock.at("2027-01-15T07:00")
    await m.tick()
    sender.fail = False
    clock.add(60)
    await m.tick()
    d = json.loads(sender.messages[-1].attachments[0].content)
    assert [p["kind"] for p in d["problems"]] == ["mail"]
    assert "HTTP 500" in d["problems"][0]["message"]


# CLI ----------------------------------------------------------------------------

def stored(home, *events):
    home.root.mkdir(parents=True, exist_ok=True)
    store = Store(home)
    t = time.time() - 60
    for e in events:
        e = dict(e, time={"secs": int(t), "nanos": 0})
        store.append(parse_line(json.dumps(e)))
    store.close()


def test_cli_digest_send(home, monkeypatch, capsys):
    sender = Sender()
    monkeypatch.setattr(delivery, "send", sender)
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    stored(home, report(0, "changed", packages=[pc("added", "a", to="1")]))
    assert main(["digest", "--send", "--home", str(home.root)]) == 0
    assert "sent to a@x.org" in capsys.readouterr().out
    assert sender.subjects() == ["fetter host · 1 change"]
    assert main(["digest", "--home", str(home.root)]) == 0
    assert "nothing recorded" in capsys.readouterr().out


def test_cli_digest_send_not_configured(home, monkeypatch, capsys):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    stored(home, report(0, "changed"))
    assert main(["digest", "--send", "--home", str(home.root)]) == 1
    assert "mail not configured" in capsys.readouterr().err


def test_cli_check_verifies_mail(home, monkeypatch, capsys):
    from tests.conftest import fake_fetter
    fake_fetter(home.fetter)
    home.config.write_text("[mail]\nenabled = true\n")
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)
    calls = []
    monkeypatch.setattr(delivery, "verify",
                        lambda tr, cr: calls.append(tr) or delivery.Result("failed", "HTTP 401"))
    assert main(["check", "--home", str(home.root)]) == 1
    assert "credentials rejected: HTTP 401 (nothing sent)" in capsys.readouterr().out
    assert main(["check", "--offline", "--home", str(home.root)]) == 0
    assert "not checked" in capsys.readouterr().out and calls == ["postmark"]


# headless ------------------------------------------------------------------------

async def test_headless_sends_immediate_alert(home):
    from fetter_scope.supervisor import Runtime
    from tests.test_supervisor import FAST, cmd
    home.root.mkdir(parents=True)
    home.config.write_text("[mail]\nenabled = true\n")
    cfg = config.load(home, environ=ENV)
    store, sender, out = Store(home), Sender(), []
    h = Runtime(cmd("--fake-report-status", "alert"), store, out=out.append, timing=FAST,
                 mailer=Mailer(cfg, store, send=sender), mail_every=3600)
    task = asyncio.create_task(h.run())
    deadline = time.monotonic() + 10
    while not any("scan (start)" in line for line in out):
        assert time.monotonic() < deadline, out
        await asyncio.sleep(0.02)
    await asyncio.wait_for(await h.supervisor.request("report"), 5)
    while not sender.messages:
        assert time.monotonic() < deadline, out
        await asyncio.sleep(0.02)
    await h.supervisor.stop()
    assert await asyncio.wait_for(task, 10) == 0
    assert sender.subjects() == ["fetter host · ALERT"]
    assert any("alert sent: fetter host · ALERT" in line for line in out)
    assert "mail ok" in out[0]


async def test_first_digest_covers_entries_stored_before_mail_started(home):
    home.root.mkdir(parents=True)
    clock = Clock("2027-01-14T12:00")
    store = Store(home, now=clock)
    log(store, clock, report(0, "changed", packages=[pc("added", "early", to="1")]))
    clock.at("2027-01-15T06:00")
    m, store, clock2, sender, _ = setup(home, start="2027-01-15T06:00")
    dg = store.read_state()["digest"]
    assert dg["last_end"] == ts("2027-01-14T12:00") and dg["last_at"] == ts("2027-01-15T06:00")
    clock2.at("2027-01-15T07:00")
    await m.tick()
    assert json.loads(sender.messages[0].attachments[0].content)["packages"][0]["key"] == "early"
