"""fetter `monitor-diff json` events (schema 1), parsed tolerantly.

Each stream line is one JSON object with `schema`, `event`, `time` (`{secs, nanos}`) and `system`,
as fetter's `monitor_diff::Event`. Unknown events and fields are kept and ignored, the rule
fetter's own schema 1 readers follow. `parse_line` never raises: a line that is not a JSON object
becomes a `raw` record, and an event with a newer schema is flagged so the header can say so.

The TypedDicts document the fields fetter-scope uses; fetter may send more.
"""
import json
from dataclasses import dataclass
from typing import Literal, NotRequired, TypedDict

SCHEMA = 1
KNOWN_EVENTS = ("start", "scan", "report", "error")


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
