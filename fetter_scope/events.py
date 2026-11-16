"""fetter `monitor-diff json` events (schema 1), parsed tolerantly.

Each stream line is one JSON object with `schema`, `event`, `time` (`{secs, nanos}`) and `system`,
as fetter's `monitor_diff::Event`. Unknown events and fields are kept and ignored, the rule
fetter's own schema 1 readers follow. `parse_line` never raises: a line that is not a JSON object
becomes a `raw` record, and an event with a newer schema is flagged so the header can say so.

The TypedDicts document the fields fetter-scope uses; fetter may send more.
"""
import json
import time as time_mod
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

SCHEMA = 1
KNOWN_EVENTS = ("start", "scan", "report", "error")

# fetter-scope's own entries, logged beside fetter's events with "source": "fetter-scope":
# launch (command, pid), fetter-exit (code, expected, restart_in), stderr (line), stdout (a
# non-JSON stdout line), control (command written), protocol-error (message), supervisor-error
# (message: restarts stopped), stale-stop (pid: a fetter left from an earlier run), mail (mail:
# digest or alert, subject, result, error).
SOURCE = "fetter-scope"
OWN_EVENTS = ("launch", "fetter-exit", "stderr", "stdout", "control", "protocol-error",
              "supervisor-error", "stale-stop", "mail")


class Duration(TypedDict):
    secs: int
    nanos: int


class SystemTag(TypedDict):
    username: str
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    logical_cores: int


class Package(TypedDict):
    ecosystem: str
    name: str
    key: str
    version: str
    direct_url: NotRequired[dict | None]
    purl: NotRequired[str]


class OriginChange(TypedDict):
    change: Literal["added", "removed"]
    ecosystem: str
    path: str


class SiteChange(TypedDict):
    change: Literal["added", "removed"]
    ecosystem: str
    kind: str
    path: str


# The functional form, since `from` is a keyword; `from` is absent if added, `to` if removed.
PackageChange = TypedDict("PackageChange", {
    "change": Literal["added", "removed", "upgraded", "downgraded", "changed"],
    "ecosystem": str,
    "site": str,
    "from": NotRequired[Package],
    "to": NotRequired[Package],
})


class Hook(TypedDict):
    name: str
    detail: str


class HookChange(TypedDict):
    change: Literal["added", "removed"]
    ecosystem: str
    site: str
    hook: Hook


class ScanDiff(TypedDict):
    origins: list[OriginChange]
    sites: list[SiteChange]
    packages: list[PackageChange]
    hooks: list[HookChange]


class Counts(TypedDict):
    origins: int
    sites: int
    packages: int


class VulnFinding(TypedDict):
    package: Package
    id: str
    source: Literal["introduced", "published", "existing"]
    summary: NotRequired[str]
    severity: NotRequired[str]
    score: NotRequired[float]
    url: str


class VulnResolved(TypedDict):
    package: Package
    id: str


class Violation(TypedDict):
    ecosystem: str
    package: str | None
    dependency: str | None
    explain: str
    sites: list[str] | None


class DiffReport(TypedDict):
    status: Literal["alert", "changed", "unchanged"]
    baseline_time: NotRequired[Duration]
    time: Duration
    changes: ScanDiff
    new_vulns: list[VulnFinding]
    resolved_vulns: list[VulnResolved]
    audit_error: NotRequired[str]
    new_violations: NotRequired[list[Violation]]
    resolved_violations: NotRequired[list[Violation]]


class _Event(TypedDict):
    schema: int
    event: str
    time: Duration
    system: SystemTag


class StartEvent(_Event):
    baseline: str                      # "rolling" or a path
    baseline_time: NotRequired[Duration]
    period: int
    report_period: int
    ecosystems: list[str]
    control: bool


class ScanEvent(_Event):
    trigger: Literal["start", "period", "request"]
    origins: int
    sites: int
    packages: int
    counts: dict[str, Counts]
    changes: ScanDiff


class ReportEvent(_Event):
    report: DiffReport


class ErrorEvent(_Event):
    message: str


#-------------------------------------------------------------------------------

@dataclass(frozen=True)
class Parsed:
    """One stream line.

    `event` is the decoded object (None for a raw line); `kind` is its `event` field, or "raw";
    `known` is whether fetter-scope uses that kind; `newer` is whether its schema is above 1.
    """
    line: str
    event: dict | None
    kind: str
    known: bool = False
    newer: bool = False
    problem: str = ""                  # why a line is raw, or what is odd about an event

    @property
    def own(self) -> bool:
        """Whether this is fetter-scope's own entry (see `own`), not a fetter event."""
        return self.event is not None and self.event.get("source") == SOURCE


def parse_line(line: str | bytes) -> Parsed:
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    line = line.rstrip("\r\n")
    try:
        obj = json.loads(line)
    except ValueError as e:
        return Parsed(line, None, "raw", problem=f"not JSON: {e}")
    if not isinstance(obj, dict):
        return Parsed(line, None, "raw", problem="not a JSON object")

    kind = obj.get("event")
    if not isinstance(kind, str):
        return Parsed(line, None, "raw", problem="no event field")
    schema = obj.get("schema")
    problem = ""
    if not isinstance(schema, int) or isinstance(schema, bool):
        problem = f"schema is {schema!r}"
        newer = False
    else:
        newer = schema > SCHEMA
    return Parsed(line, obj, kind, known=kind in KNOWN_EVENTS, newer=newer, problem=problem)


def duration_seconds(d: object) -> float | None:
    """A fetter `{secs, nanos}` as float seconds since the epoch; None if absent or malformed."""
    if not isinstance(d, dict):
        return None
    secs, nanos = d.get("secs"), d.get("nanos", 0)
    if not isinstance(secs, int) or not isinstance(nanos, int):
        return None
    return secs + nanos / 1e9


def own(kind: str, now: float | None = None, **fields) -> Parsed:
    """A fetter-scope entry, shaped like an event so one log and one reader hold both."""
    t = time_mod.time() if now is None else now
    secs = int(t)
    obj = {"schema": SCHEMA, "event": kind, "source": SOURCE,
           "time": {"secs": secs, "nanos": int(round((t - secs) * 1e9))}, **fields}
    return Parsed(json.dumps(obj, separators=(",", ":")), obj, kind, known=kind in OWN_EVENTS)


#-------------------------------------------------------------------------------
# one-line summaries (headless output, the Log tab)

def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _diff_counts(diff: object) -> str:
    """`+2 -1 packages, +1 hook` for a ScanDiff; "" if empty."""
    if not isinstance(diff, dict):
        return ""
    parts = []
    for section, word in (("origins", "origin"), ("sites", "site"), ("packages", "package"),
                          ("hooks", "hook")):
        items = diff.get(section) or []
        if not isinstance(items, list) or not items:
            continue
        by: dict[str, int] = {}
        for c in items:
            k = c.get("change", "?") if isinstance(c, dict) else "?"
            by[k] = by.get(k, 0) + 1
        signs = {"added": "+", "removed": "-", "upgraded": "↑", "downgraded": "↓", "changed": "~"}
        counts = " ".join(f"{signs.get(k, k + ' ')}{n}" for k, n in sorted(by.items()))
        parts.append(f"{counts} {word if len(items) == 1 else word + 's'}")
    return ", ".join(parts)


def summary(p: Parsed) -> str:
    """One line for a stream entry, without its time."""
    e = p.event
    if e is None:
        return f"raw: {p.line[:200]}"
    g = e.get
    prefix = f"[schema {g('schema')}] " if p.newer else ""
    match p.kind:
        case "start":
            base = g("baseline", "?")
            text = (f"start: baseline {base}, scan every {g('period')}s, report every "
                    f"{g('report_period')}s, {', '.join(g('ecosystems') or []) or 'no ecosystems'}"
                    f"{'' if g('control') else ', no control'}")
        case "scan":
            text = (f"scan ({g('trigger', 'period')}): {_plural(g('origins', 0), 'origin')}, "
                    f"{_plural(g('sites', 0), 'site')}, {_plural(g('packages', 0), 'package')}")
            if d := _diff_counts(g("changes")):
                text += f"; {d}"
        case "report":
            r = g("report") or {}
            bits = [x for x in (
                _diff_counts(r.get("changes")),
                _plural(len(r.get("new_vulns") or []), "new vuln") if r.get("new_vulns") else "",
                _plural(len(r.get("resolved_vulns") or []), "resolved vuln") if r.get("resolved_vulns") else "",
                _plural(len(r.get("new_violations") or []), "new violation") if r.get("new_violations") else "",
                f"audit error: {r['audit_error']}" if r.get("audit_error") else "",
            ) if x]
            status = r.get("status", "?")
            text = f"report {'ALERT' if status == 'alert' else status}"
            if bits:
                text += ": " + "; ".join(bits)
        case "error":
            text = f"error: {g('message', '')}"
        case "launch":
            text = f"launched fetter (pid {g('pid')})"
        case "fetter-exit":
            text = f"fetter exited with {g('code')}" + ("" if g("expected") else " (unexpected)")
            if g("restart_in") is not None:
                text += f"; restarting in {g('restart_in'):g}s"
        case "stderr":
            text = f"stderr: {g('line', '')}"
        case "stdout":
            text = f"stdout (not an event): {g('line', '')[:200]}"
        case "control":
            text = f"sent {g('command')}"
        case "protocol-error" | "supervisor-error":
            text = f"{p.kind}: {g('message', '')}"
        case "mail":
            text = f"{g('mail', 'mail')} {g('result')}: {g('subject', '')}"
            if g("error"):
                text += f" ({g('error')})"
        case "stale-stop":
            text = f"stopped a fetter left running by an earlier fetter-scope (pid {g('pid')})"
        case _:
            text = f"{p.kind} (unknown event)"
    return prefix + text
