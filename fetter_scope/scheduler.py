"""When to mail, and the mailing itself: digests on a schedule, immediate alerts, retries.

The timing functions are pure given "now". `Mailer` keeps its state in state.json:

    digest: last_end (where the next digest's period starts), last_at (when the last digest
            was made: the schedule follows it), last_sent, last_result, last_error, failures,
            retry_at
    alerts: covered_until (alert mails cover reports after it), last_sent, pending,
            failures, retry_at, windows (the [start, end) spans alert mails covered, to mark
            those items "mailed" in the digest)
    mail_history: the last sends, newest last

A digest is due at the first boundary after `last_at` (boundaries: `every`, aligned to `at`
and `weekday`, in local wall-clock time). A period ends just after the latest entry it includes,
not at "now": fetter writes in time order, so an event still in the pipe when a mail is built
falls in the next period instead of being lost between the two. A boundary that passed while fetter-scope was not
running makes the digest due at the next start; it covers everything up to then. A failed send
leaves `last_end` where it was and retries with backoff up to an hour, so nothing is dropped.
"""
import asyncio
import json
import time
from collections.abc import Callable
from datetime import datetime, timedelta

from fetter_scope import delivery, render
from fetter_scope.config import WEEKDAYS, Config, MailConfig
from fetter_scope.digest import fold, pending_window
from fetter_scope.events import Parsed, duration_seconds, own
from fetter_scope.store import Store

DAY = 86400
# A Monday at local midnight: boundaries are this (moved to `at` and `weekday`) plus multiples
# of `every`, so a "2d" or "6h" schedule is the same from one run to the next.
REFERENCE = datetime(2024, 1, 1)
BACKOFF_INITIAL = 60
BACKOFF_MAX = 3600
HISTORY = 100
TICK = 30
HORIZON_STEP = 1e-6                     # past an entry's time (fetter's times have nanoseconds)


def next_boundary(after: float, mail: MailConfig) -> float:
    """The first digest boundary strictly after `after` (epoch seconds)."""
    hour, minute = mail.at
    ref = REFERENCE.replace(hour=hour, minute=minute)
    if mail.weekday and mail.every == 7 * DAY:
        ref += timedelta(days=WEEKDAYS.index(mail.weekday))
    every = timedelta(seconds=mail.every)
    local = datetime.fromtimestamp(after)            # naive local: days stay at `at` over DST
    candidate = ref + ((local - ref) // every + 1) * every
    while candidate.timestamp() <= after:            # a DST shift can leave it a step behind
        candidate += every
    return candidate.timestamp()


def backoff(failures: int) -> float:
    """Seconds before retrying after `failures` failed sends in a row."""
    return min(BACKOFF_INITIAL * 2 ** max(failures - 1, 0), BACKOFF_MAX)


def _num(x) -> float | None:
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) else None


def _stamp(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H%M", time.localtime(t))


class Mailer:
    """Digest and alert mail for one fetter-scope home."""

    def __init__(self, cfg: Config, store: Store, *,
                 now: Callable[[], float] = time.time,
                 send: Callable[..., delivery.Result] | None = None,
                 transports: delivery.Transports | None = None,
                 emit: Callable[[Parsed], None] | None = None):
        self.cfg = cfg
        self.store = store
        self.now = now
        self._send = send or delivery.send
        self.transports = transports
        self.emit = emit
        self._lock = asyncio.Lock()

    # state ----------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self.cfg.mail.enabled

    @property
    def configured(self) -> bool:
        return not self.cfg.mail_missing

    def _part(self, name: str) -> dict:
        part = self.store.read_state().get(name)
        return dict(part) if isinstance(part, dict) else {}

    def _save(self, name: str, part: dict) -> None:
        self.store.update_state(**{name: part})

    def start(self) -> None:
        """Without digest state, the first digest covers everything stored (nothing recorded is
        left unmailed) and is due at the next boundary; alert mails cover what arrives from now."""
        now = self.now()
        dg, al = self._part("digest"), self._part("alerts")
        if _num(dg.get("last_end")) is None or _num(dg.get("last_at")) is None:
            dg.setdefault("last_end", self.digest_start(now))
            dg.setdefault("last_at", now)
            self._save("digest", dg)
        if _num(al.get("covered_until")) is None:
            al["covered_until"] = now
            self._save("alerts", al)

    def next_digest_at(self) -> float | None:
        dg = self._part("digest")
        last = _num(dg.get("last_at"))
        if last is None:
            last = _num(dg.get("last_end"))
        if last is None:
            return None
        due = next_boundary(last, self.cfg.mail)
        retry = _num(dg.get("retry_at"))
        return max(due, retry) if retry else due

    def next_alert_at(self) -> float | None:
        al = self._part("alerts")
        if not al.get("pending"):
            return None
        times = [_num(al.get("retry_at")) or 0]
        if (last := _num(al.get("last_sent"))) is not None:
            times.append(last + self.cfg.mail.alert_min_interval)
        return max(times)

    def status(self) -> str:
        if not self.enabled:
            return "mail disabled"
        if not self.configured:
            return f"mail not configured ({', '.join(self.cfg.mail_missing)})"
        dg = self._part("digest")
        if dg.get("failures"):
            return f"mail failing: {dg.get('last_error', '')}"
        return "mail ok"

    # events ---------------------------------------------------------------------

    def on_entry(self, p: Parsed) -> bool:
        """Note an alert report for an immediate alert mail; True if one is now pending."""
        if (self.enabled and self.cfg.mail.alerts == "immediate" and p.kind == "report"
                and not p.own and isinstance(p.event.get("report"), dict)
                and p.event["report"].get("status") == "alert"):
            al = self._part("alerts")
            if not al.get("pending"):
                al["pending"] = True
                self._save("alerts", al)
            return True
        return False

    # building -------------------------------------------------------------------

    def build(self, start: float, end: float) -> dict:
        """The digest of [start, end); `self.horizon` is set to where the next period starts:
        just after the latest entry included (or `end` if there was none)."""
        shown_end, end = end, end + HORIZON_STEP     # include an entry stamped at `end` itself
        entries = [p.event for p in self.store.iter_entries(since=start) if p.event is not None]
        times = [t for e in entries if (t := duration_seconds(e.get("time"))) is not None
                 and start <= t < end]
        self.horizon = min(max(times) + HORIZON_STEP, end) if times else shown_end
        d = fold(entries, start, end, period=self.cfg.fetter.period,
                 baseline=self.cfg.fetter.baseline or "rolling")
        d["end"] = shown_end
        windows = self._part("alerts").get("windows") or []
        if windows:
            for items in (d["vulns"]["new"], d["hooks"]["added"], d["violations"]["new"],
                          [p for p in d["packages"] if p["change"] == "downgraded"]):
                for x in items:
                    t = x.get("first")
                    x["mailed"] = t is not None and any(a <= t < b for a, b in windows)
        return d

    def digest_start(self, now: float) -> float:
        """The pending period's start: the last digest's end, else the first stored entry."""
        first = next((t for p in self.store.iter_entries() if p.event is not None
                      and (t := duration_seconds(p.event.get("time"))) is not None), None)
        return pending_window(self.store.read_state(), first, now)[0]

    def pending(self) -> dict:
        now = self.now()
        return self.build(self.digest_start(now), now)

    def digest_message(self, d: dict) -> delivery.Message:
        html, text, _ = render.fit(d)
        attachment = delivery.Attachment(
            f"fetter-digest-{_stamp(d['end'])}.json",
            json.dumps(d, indent=2, ensure_ascii=False).encode())
        return delivery.Message(render.subject(d, self.cfg.mail.subject_prefix), html, text,
                                (attachment,))

    def alert_message(self, d: dict) -> delivery.Message:
        html, text, _ = render.fit(d, attached=False, alerts_only=True)
        return delivery.Message(render.subject(d, self.cfg.mail.subject_prefix), html, text)

    # sending --------------------------------------------------------------------

    async def _deliver(self, kind: str, m: delivery.Message) -> delivery.Result:
        result = await asyncio.to_thread(self._send, m, self.cfg.mail.transport,
                                         self.cfg.credentials, self.transports)
        self._record(kind, m.subject, result)
        return result

    def _record(self, kind: str, subject: str, result: delivery.Result) -> None:
        entry = {"time": self.now(), "kind": kind, "subject": subject,
                 "result": result.status, **({"error": result.error} if result.error else {})}
        history = self.store.read_state().get("mail_history")
        history = (history if isinstance(history, list) else [])[-(HISTORY - 1):] + [entry]
        self.store.update_state(mail_history=history)
        if self.emit is not None:
            self.emit(own("mail", now=entry["time"], mail=kind, subject=subject,
                          result=result.status,
                          **({"error": result.error} if result.error else {})))

    def _save_files(self, kind: str, t: float, m: delivery.Message, d: dict) -> None:
        self.store.home.mail.mkdir(parents=True, exist_ok=True)
        base = _stamp(t) + ("" if kind == "digest" else f"-{kind}")
        name, n = base, 1
        while (self.store.home.mail / f"{name}.json").exists():
            n += 1
            name = f"{base}-{n}"
        stem = self.store.home.mail / name
        stem.with_suffix(".json").write_text(json.dumps(
            {"kind": kind, "subject": m.subject, "sent": t, "digest": d},
            indent=2, ensure_ascii=False))
        stem.with_suffix(".html").write_text(m.html)
        stem.with_suffix(".txt").write_text(m.text)

    async def send_digest(self, force: bool = False) -> delivery.Result | None:
        """Send the digest of the period since the last one, ending now. Without `force`, an
        uneventful digest is not sent (unless `send_unchanged`) but its period still ends.
        Returns None when nothing was sent for that reason."""
        async with self._lock:
            return await self._send_digest(force)

    async def _send_digest(self, force: bool) -> delivery.Result | None:
        now = self.now()
        dg = self._part("digest")
        d = self.build(self.digest_start(now), now)
        horizon = self.horizon
        if not (force or d["counts"]["eventful"] or self.cfg.mail.send_unchanged):
            dg.update(last_end=horizon, last_at=now, last_result="unchanged, not sent",
                      failures=0, retry_at=None)
            self._save("digest", dg)
            self._prune_windows(horizon)
            return None
        m = self.digest_message(d)
        result = await self._deliver("digest", m)
        dg = self._part("digest")
        if result.ok:
            self._save_files("digest", now, m, d)
            dg.update(last_end=horizon, last_at=now, last_sent=now, last_result=result.status,
                      last_error="", failures=0, retry_at=None)
            self._prune_windows(horizon)
        else:
            failures = int(dg.get("failures") or 0) + 1
            dg.update(last_result=result.status, last_error=result.error, failures=failures,
                      retry_at=now + backoff(failures))
        self._save("digest", dg)
        return result

    def _prune_windows(self, digest_end: float) -> None:
        al = self._part("alerts")
        windows = [w for w in al.get("windows") or [] if w[1] > digest_end]
        if windows != (al.get("windows") or []):
            al["windows"] = windows
            self._save("alerts", al)

    async def _send_alert(self, now: float) -> delivery.Result | None:
        al = self._part("alerts")
        start = _num(al.get("covered_until"))
        start = now if start is None else min(start, now)
        d = self.build(start, now)
        horizon = self.horizon
        if not d["alert_reports"]:            # nothing to say (e.g. already covered)
            al.update(pending=False)
            self._save("alerts", al)
            return None
        m = self.alert_message(d)
        result = await self._deliver("alert", m)
        al = self._part("alerts")
        if result.ok:
            self._save_files("alert", now, m, d)
            windows = list(al.get("windows") or []) + [[start, horizon]]
            al.update(pending=False, covered_until=horizon, last_sent=now, failures=0,
                      retry_at=None, windows=windows, last_error="")
        else:
            failures = int(al.get("failures") or 0) + 1
            al.update(failures=failures, retry_at=now + backoff(failures),
                      last_error=result.error)
        self._save("alerts", al)
        return result

    async def tick(self) -> list[delivery.Result]:
        """Send what is due: a pending alert mail, then the digest."""
        if not (self.enabled and self.configured):
            return []
        async with self._lock:
            results = []
            now = self.now()
            due_alert = self.next_alert_at()
            if due_alert is not None and now >= due_alert:
                if (r := await self._send_alert(now)) is not None:
                    results.append(r)
            due_digest = self.next_digest_at()
            if due_digest is not None and now >= due_digest:
                if (r := await self._send_digest(force=False)) is not None:
                    results.append(r)
            return results
