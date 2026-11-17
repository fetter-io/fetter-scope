"""What the TUI shows, folded from stream entries; no Textual here, so it is tested directly.

`Model.add` takes every entry in order (fetter's events and fetter-scope's own, as stored or as
they arrive) and keeps: the latest start and scan, scan history, reports, one row per alert item,
package change rows, the live feed of scan changes, the log, and fetter's state. Its `inventory`
(open vulnerabilities per site, over all history) starts from the home's saved one.
"""
from collections import deque
from dataclasses import dataclass, field, replace

from fetter_scope.digest import fold
from fetter_scope.events import Parsed, duration_seconds
from fetter_scope.sites import Inventory

ALERT_TYPES = ("vuln", "hook", "downgrade", "violation")


def _t(e: dict) -> float | None:
    return duration_seconds(e.get("time"))


def _ver(pkg: dict | None) -> str:
    return "" if not pkg else str(pkg.get("version", ""))


@dataclass(frozen=True)
class AlertItem:
    key: str
    type: str                     # vuln, hook, downgrade, violation
    ecosystem: str
    subject: str                  # the package, or the hook's name
    site: str
    detail: str
    time: float
    data: dict                    # the fetter record (finding, hook change, package change, violation)
    score: float | None = None


def alert_items(report: dict, t: float, first: int = 0) -> list[AlertItem]:
    """One item per alert finding in a report, in fetter's order. Keys are sequential from
    `first`: a report can name the same advisory for one package at two versions (two sites),
    so no combination of its fields is unique."""
    out = []
    for v in report.get("new_vulns") or []:
        pkg = v.get("package") or {}
        score = v.get("score")
        detail = " · ".join(x for x in (
            v.get("id"), f"CVSS {score:g}" if isinstance(score, (int, float)) else "",
            v.get("source"), v.get("summary")) if x)
        out.append(AlertItem("", "vuln", pkg.get("ecosystem", ""),
                             f"{pkg.get('name', pkg.get('key', '?'))} {_ver(pkg)}".strip(),
                             ", ".join(s for s in v.get("sites") or [] if isinstance(s, str)),
                             detail, t, v, score if isinstance(score, (int, float)) else None))
    ch = report.get("changes") or {}
    for h in ch.get("hooks") or []:
        if h.get("change") != "added":
            continue
        hook = h.get("hook") or {}
        lines = (hook.get("detail") or "").strip().splitlines()
        out.append(AlertItem("", "hook",
                             h.get("ecosystem", ""), hook.get("name", "?"), h.get("site", ""),
                             lines[0][:120] if lines else "", t, h))
    for p in ch.get("packages") or []:
        if p.get("change") != "downgraded":
            continue
        pkg = p.get("to") or p.get("from") or {}
        out.append(AlertItem("", "downgrade",
                             p.get("ecosystem", ""), pkg.get("name", pkg.get("key", "?")),
                             p.get("site", ""), f"{_ver(p.get('from'))} → {_ver(p.get('to'))}", t, p))
    for v in report.get("new_violations") or []:
        out.append(AlertItem("", "violation", v.get("ecosystem", ""),
                             v.get("package") or v.get("dependency") or "?",
                             ", ".join(v.get("sites") or []), v.get("explain", ""), t, v))
    return [replace(item, key=f"alert:{first + i}") for i, item in enumerate(out)]


@dataclass(frozen=True)
class ChangeRow:
    key: str
    change: str                   # added, removed, upgraded, downgraded, changed
    ecosystem: str
    site: str
    name: str
    frm: str
    to: str
    time: float | None


def report_change_rows(report: dict, t: float, first: int = 0) -> list[ChangeRow]:
    """A report's package changes; keys are sequential from `first`."""
    rows = []
    for c in (report.get("changes") or {}).get("packages") or []:
        pkg = c.get("to") or c.get("from") or {}
        rows.append(ChangeRow(f"change:{first + len(rows)}", c.get("change", "?"),
                              c.get("ecosystem", ""), c.get("site", ""),
                              pkg.get("name", pkg.get("key", "?")), _ver(c.get("from")),
                              _ver(c.get("to")), t))
    return rows


def digest_change_rows(d: dict) -> list[ChangeRow]:
    return [ChangeRow(f"net:{p['site']}:{p['key']}", p["change"], p["ecosystem"], p["site"],
                      p["name"], _ver(p.get("from")), _ver(p.get("to")), p.get("last"))
            for p in d["packages"]]


@dataclass(frozen=True)
class LiveRow:
    key: str
    time: float
    trigger: str
    what: str                     # package, site, origin, hook
    change: str
    ecosystem: str
    name: str
    detail: str


def scan_live_rows(scan: dict, t: float, n: int) -> list[LiveRow]:
    ch = scan.get("changes") or {}
    trig = scan.get("trigger", "period")
    rows = []
    for c in ch.get("packages") or []:
        pkg = c.get("to") or c.get("from") or {}
        frm, to = _ver(c.get("from")), _ver(c.get("to"))
        rows.append(("package", c.get("change", "?"), c.get("ecosystem", ""),
                     pkg.get("name", pkg.get("key", "?")),
                     f"{frm} → {to}" if frm and to else (to or frm), c.get("site", "")))
    for c in ch.get("hooks") or []:
        rows.append(("hook", c.get("change", "?"), c.get("ecosystem", ""),
                     (c.get("hook") or {}).get("name", "?"), "", c.get("site", "")))
    for what in ("sites", "origins"):
        for c in ch.get(what) or []:
            rows.append((what[:-1], c.get("change", "?"), c.get("ecosystem", ""),
                         c.get("path", "?"), c.get("kind", ""), ""))
    return [LiveRow(f"live:{n}:{i}", t, trig, w, chg, eco, name,
                    " · ".join(x for x in (detail, site) if x))
            for i, (w, chg, eco, name, detail, site) in enumerate(rows)]


@dataclass
class Model:
    feed_limit: int = 2000
    log_limit: int = 10_000
    attached: bool = False

    entries: list[dict] = field(default_factory=list)
    log: deque = field(default_factory=deque)
    live: deque = field(default_factory=deque)
    alerts: list[AlertItem] = field(default_factory=list)
    changes: list[ChangeRow] = field(default_factory=list)
    reports: list[tuple[float, dict]] = field(default_factory=list)
    scans: list[tuple[float, int, dict]] = field(default_factory=list)
    start: dict | None = None
    system: dict = field(default_factory=dict)
    last_scan: dict | None = None
    newer: int | None = None      # the highest schema above 1 seen
    fetter: str = "not running"   # starting, running, restarting, not running, failed, attached
    inventory: Inventory = field(default_factory=Inventory)   # open vulnerabilities per site
    version: int = 0              # bumped on every add, for change detection

    def __post_init__(self):
        self.live = deque(maxlen=self.feed_limit)
        self.log = deque(maxlen=self.log_limit)
        if self.attached:
            self.fetter = "attached"

    def add(self, p: Parsed) -> None:
        self.version += 1
        self.log.append(p)
        e = p.event
        if e is None:
            return
        self.entries.append(e)
        t = _t(e)
        if p.newer:
            self.newer = max(self.newer or 0, e.get("schema", 0))
        if isinstance(e.get("system"), dict):
            self.system = e["system"]
        if p.own:
            if self.attached:
                return
            match p.kind:
                case "launch":
                    self.fetter = "starting"
                case "fetter-exit":
                    self.fetter = "restarting" if e.get("restart_in") is not None else "not running"
                case "supervisor-error":
                    self.fetter = "failed"
            return
        self.inventory.apply(e)
        match p.kind:
            case "start":
                self.start = e
                if not self.attached:
                    self.fetter = "running"
            case "scan":
                self.last_scan = e
                if t is not None:
                    self.scans.append((t, int(e.get("packages") or 0), e.get("counts") or {}))
                    # newest scan first; within a scan, fetter's order
                    for row in reversed(scan_live_rows(e, t, len(self.scans))):
                        self.live.appendleft(row)
            case "report":
                r = e.get("report")
                if isinstance(r, dict):
                    rt = duration_seconds(r.get("time")) or t or 0.0
                    self.reports.append((rt, r))
                    self.alerts.extend(alert_items(r, rt, len(self.alerts)))
                    self.changes.extend(report_change_rows(r, rt, len(self.changes)))

    # derived ----------------------------------------------------------------------

    @property
    def period(self) -> int | None:
        p = (self.start or {}).get("period")
        return p if isinstance(p, int) and p > 0 else None

    def next_scan_at(self) -> float | None:
        if self.last_scan is None or self.period is None:
            return None
        t = _t(self.last_scan)
        return None if t is None else t + self.period

    def counts(self) -> dict[str, dict]:
        return (self.last_scan or {}).get("counts") or {}

    def ecosystems(self) -> list[str]:
        """The ecosystems worth offering in the selector: those with packages in the latest scan,
        and any named by a report or scan row (an ecosystem since emptied still has history)."""
        seen = {eco for eco, c in self.counts().items() if (c or {}).get("packages")}
        seen.update(a.ecosystem for a in self.alerts)
        seen.update(c.ecosystem for c in self.changes)
        seen.update(r.ecosystem for r in self.live)
        seen.discard("")
        return sorted(seen)

    def dropped_to_zero(self) -> list[str]:
        """Ecosystems with no packages now that had some earlier in the session: more likely a
        scan problem than removals."""
        now = self.counts()
        had = {eco for _, _, counts in self.scans[:-1] for eco, c in counts.items()
               if (c or {}).get("packages")}
        return sorted(eco for eco in had if not (now.get(eco) or {}).get("packages"))

    def latest_report(self) -> tuple[float, dict] | None:
        return self.reports[-1] if self.reports else None

    def digest(self, start: float, end: float, period: int | None = None,
               baseline: str = "rolling") -> dict:
        return fold(self.entries, start, end, period=self.period or period,
                    baseline=(self.start or {}).get("baseline") or baseline)


def matches(query: str, fields: dict[str, str]) -> bool:
    """A filter: `key:value` tokens match that field, other words match any field; all
    case-insensitive substrings, all must match."""
    for token in query.lower().split():
        key, sep, value = token.partition(":")
        if sep and key in fields:
            if value not in str(fields[key]).lower():
                return False
        elif not any(token in str(v).lower() for v in fields.values()):
            return False
    return True
