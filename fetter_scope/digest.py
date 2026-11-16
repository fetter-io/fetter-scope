"""Fold a period's fetter reports (and what else happened) into one digest.

fetter compares each report with the last reported state (a rolling baseline), so a digest
covering several reports chains them: per item, the earliest state and the latest one give the
net change, and an item that ends where it began is *transient* (itself a signal: a package
installed and removed between two digests). With a fixed baseline (`--baseline FILE`) every report
is against the same baseline, so the last report is the net and items in earlier reports but not
the last are transient.

`fold` is pure: event dicts in, a JSON-serializable digest dict out. Every finding comes from a
fetter event; nothing is re-derived, and versions are never ordered in Python (see `_net_kind`).
"""
import json
from collections.abc import Iterable
from dataclasses import dataclass, field

from fetter_scope.events import SOURCE, duration_seconds

DIGEST_VERSION = 1

# own entries reported as problems
_PROBLEM_KINDS = ("protocol-error", "supervisor-error")


def _t(event: dict) -> float | None:
    return duration_seconds(event.get("time"))


def _pkg_state(pkg: dict | None) -> tuple | None:
    """What makes two package states the same: the version and the source."""
    if pkg is None:
        return None
    return (pkg.get("version"), json.dumps(pkg.get("direct_url"), sort_keys=True))


def _sort_key(*parts) -> tuple:
    return tuple("" if p is None else str(p) for p in parts)


#-------------------------------------------------------------------------------
# keyed presence: origins, sites, hooks, vulnerabilities, violations

@dataclass
class _Track:
    first_change: str              # "added" or "removed": the first seen
    last_change: str
    first_item: dict
    last_item: dict
    first: float | None
    last: float | None
    steps: int = 1


class _Presence:
    """Items that are added and removed over the period, by key."""

    def __init__(self):
        self.items: dict[tuple, _Track] = {}

    def see(self, key: tuple, change: str, item: dict, t: float | None) -> None:
        tr = self.items.get(key)
        if tr is None:
            self.items[key] = _Track(change, change, item, item, t, t)
        else:
            tr.last_change, tr.last_item, tr.last, tr.steps = change, item, t, tr.steps + 1

    def net(self) -> tuple[list[_Track], list[_Track], list[_Track]]:
        """(added, removed, transient): present at the end but not the start, the reverse,
        and the same at both ends (it changed in between)."""
        added, removed, transient = [], [], []
        for key in sorted(self.items, key=lambda k: _sort_key(*k)):
            tr = self.items[key]
            was_present = tr.first_change == "removed"
            is_present = tr.last_change == "added"
            if was_present == is_present:
                transient.append(tr)
            elif is_present:
                added.append(tr)
            else:
                removed.append(tr)
        return added, removed, transient


#-------------------------------------------------------------------------------
# packages

@dataclass
class _Pkg:
    ecosystem: str
    site: str
    key: str
    first_from: dict | None
    last_to: dict | None
    kinds: list[str]
    last_step_from: dict | None
    versions: list[str]
    first: float | None
    last: float | None


def _version(pkg: dict | None) -> str:
    """A package's version, or "(none)" for a side that does not exist (added or removed)."""
    return "(none)" if pkg is None else str(pkg.get("version", ""))


def _net_kind(p: _Pkg) -> str:
    """The net change's kind from fetter's classifications, never by ordering versions:
    the last step's kind if it spans the same versions as the net change, else the common kind
    if every step was an upgrade (or every one a downgrade), else "changed"."""
    if p.first_from is None:
        return "added"
    if p.last_to is None:
        return "removed"
    if _pkg_state(p.last_step_from) == _pkg_state(p.first_from):
        return p.kinds[-1]
    if len(set(p.kinds)) == 1 and p.kinds[0] in ("upgraded", "downgraded"):
        return p.kinds[0]
    return "changed"


class _Packages:
    def __init__(self):
        self.items: dict[tuple, _Pkg] = {}

    def see(self, c: dict, t: float | None) -> None:
        key = (c.get("ecosystem", ""), c.get("site", ""),
               (c.get("to") or c.get("from") or {}).get("key", ""))
        frm, to = c.get("from"), c.get("to")
        p = self.items.get(key)
        if p is None:
            self.items[key] = _Pkg(*key, frm, to, [c.get("change", "changed")], frm,
                                   [_version(frm), _version(to)], t, t)
        else:
            p.last_to, p.last_step_from, p.last = to, frm, t
            p.kinds.append(c.get("change", "changed"))
            p.versions.append(_version(to))

    def net(self) -> tuple[list[dict], list[dict]]:
        changes, transient = [], []
        for key in sorted(self.items, key=lambda k: _sort_key(*k)):
            p = self.items[key]
            pkg = p.last_to or p.first_from or {}
            base = {"ecosystem": p.ecosystem, "site": p.site, "key": p.key,
                    "name": pkg.get("name", p.key), "first": p.first, "last": p.last}
            if _pkg_state(p.first_from) == _pkg_state(p.last_to):
                what = ("installed then removed" if p.first_from is None
                        else "changed then restored")
                transient.append(base | {"what": what, "versions": _dedupe_runs(p.versions),
                                         "steps": len(p.kinds)})
            else:
                changes.append(base | {"change": _net_kind(p), "from": p.first_from,
                                       "to": p.last_to, "steps": len(p.kinds)})
        return changes, transient


def _dedupe_runs(xs: list[str]) -> list[str]:
    out = []
    for x in xs:
        if not out or out[-1] != x:
            out.append(x)
    return out


#-------------------------------------------------------------------------------

def _keys(report: dict) -> dict[str, dict[tuple, tuple[str, dict]]]:
    """A report's items by category and key, with their change: for the fixed-baseline fold."""
    ch = report.get("changes") or {}
    out: dict[str, dict] = {k: {} for k in ("packages", "origins", "sites", "hooks", "vulns",
                                            "violations")}
    for c in ch.get("packages") or []:
        k = (c.get("ecosystem"), c.get("site"), (c.get("to") or c.get("from") or {}).get("key"))
        out["packages"][k] = (c.get("change"), c)
    for c in ch.get("origins") or []:
        out["origins"][(c.get("ecosystem"), c.get("path"))] = (c.get("change"), c)
    for c in ch.get("sites") or []:
        out["sites"][(c.get("ecosystem"), c.get("path"))] = (c.get("change"), c)
    for c in ch.get("hooks") or []:
        out["hooks"][_hook_key(c)] = (c.get("change"), c)
    for v in report.get("new_vulns") or []:
        out["vulns"][_vuln_key(v)] = ("added", v)
    for v in report.get("resolved_vulns") or []:
        out["vulns"][_vuln_key(v)] = ("removed", v)
    for v in report.get("new_violations") or []:
        out["violations"][_violation_key(v)] = ("added", v)
    for v in report.get("resolved_violations") or []:
        out["violations"][_violation_key(v)] = ("removed", v)
    return out


def _hook_key(c: dict) -> tuple:
    h = c.get("hook") or {}
    return (c.get("ecosystem"), c.get("site"), h.get("name"), h.get("detail"))


def _vuln_key(v: dict) -> tuple:
    pkg = v.get("package") or {}
    return (pkg.get("ecosystem"), pkg.get("key"), v.get("id"))


def _violation_key(v: dict) -> tuple:
    return (v.get("ecosystem"), json.dumps(v, sort_keys=True))


@dataclass
class _Fold:
    packages: _Packages = field(default_factory=_Packages)
    origins: _Presence = field(default_factory=_Presence)
    sites: _Presence = field(default_factory=_Presence)
    hooks: _Presence = field(default_factory=_Presence)
    vulns: _Presence = field(default_factory=_Presence)
    violations: _Presence = field(default_factory=_Presence)

    def report(self, r: dict, t: float | None) -> None:
        ch = r.get("changes") or {}
        for c in ch.get("packages") or []:
            self.packages.see(c, t)
        for c in ch.get("origins") or []:
            self.origins.see((c.get("ecosystem"), c.get("path")), c.get("change"), c, t)
        for c in ch.get("sites") or []:
            self.sites.see((c.get("ecosystem"), c.get("path")), c.get("change"), c, t)
        for c in ch.get("hooks") or []:
            self.hooks.see(_hook_key(c), c.get("change"), c, t)
        for v in r.get("new_vulns") or []:
            self.vulns.see(_vuln_key(v), "added", v, t)
        for v in r.get("resolved_vulns") or []:
            self.vulns.see(_vuln_key(v), "removed", v, t)
        for v in r.get("new_violations") or []:
            self.violations.see(_violation_key(v), "added", v, t)
        for v in r.get("resolved_violations") or []:
            self.violations.see(_violation_key(v), "removed", v, t)


def _with_times(tr: _Track, item: dict) -> dict:
    return item | {"first": tr.first, "last": tr.last}


def _alert_counts(r: dict) -> dict:
    ch = r.get("changes") or {}
    return {
        "new_vulns": len(r.get("new_vulns") or []),
        "new_hooks": sum(1 for c in ch.get("hooks") or [] if c.get("change") == "added"),
        "downgrades": sum(1 for c in ch.get("packages") or [] if c.get("change") == "downgraded"),
        "new_violations": len(r.get("new_violations") or []),
    }


def _fixed_transients(reports: list[tuple[float | None, dict]]) -> dict[str, list]:
    """Items in earlier fixed-baseline reports that are gone from the last one."""
    last = _keys(reports[-1][1])
    seen: dict[str, dict[tuple, dict]] = {k: {} for k in last}
    for t, r in reports[:-1]:
        for cat, items in _keys(r).items():
            for k, (change, item) in items.items():
                if k not in last[cat]:
                    rec = seen[cat].setdefault(k, {"item": item, "change": change,
                                                   "first": t, "last": t})
                    rec["last"] = t
    out = {}
    for cat, recs in seen.items():
        rows = []
        for k in sorted(recs, key=lambda k: _sort_key(*k)):
            rec = recs[k]
            rows.append({"change": rec["change"], "item": rec["item"],
                         "first": rec["first"], "last": rec["last"]})
        out[cat] = rows
    return out


def fold(entries: Iterable[dict], start: float, end: float, *,
         period: float | None = None, baseline: str = "rolling") -> dict:
    """Fold the entries with times in [start, end) into a digest.

    `entries` are event dicts in the order received: fetter's events and fetter-scope's own.
    `period` (seconds between scans) and `baseline` ("rolling" or a fixed file) describe fetter
    when no `start` event in the window says otherwise; `period` enables the missing-scan check.
    """
    reports: list[tuple[float | None, dict]] = []
    problems: list[dict] = []
    scan_times: list[float] = []
    alert_reports: list[dict] = []
    system: dict = {}
    last_scan: dict | None = None
    starts = 0
    fixed_flags: list[bool] = []

    for e in entries:
        t = _t(e)
        if t is None or not (start <= t < end):
            continue
        kind = e.get("event")
        if isinstance(e.get("system"), dict):
            system = e["system"]
        if e.get("source") == SOURCE:
            if kind == "fetter-exit" and not e.get("expected"):
                msg = f"fetter exited with {e.get('code')}"
                if e.get("message"):
                    msg += f": {e['message']}"
                problems.append({"kind": "fetter-exit", "time": t, "message": msg})
            elif kind == "mail" and e.get("result") == "failed":
                problems.append({"kind": "mail", "time": t,
                                 "message": f"{e.get('mail', 'mail')} mail failed: {e.get('error', '')}"})
            elif kind in _PROBLEM_KINDS:
                problems.append({"kind": kind, "time": t, "message": str(e.get("message", ""))})
            continue
        match kind:
            case "start":
                starts += 1
                if isinstance(e.get("period"), int) and e["period"] > 0:
                    period = e["period"]
                if isinstance(e.get("baseline"), str):
                    baseline = e["baseline"]
            case "scan":
                scan_times.append(t)
                last_scan = e
            case "report":
                r = e.get("report")
                if not isinstance(r, dict):
                    continue
                rt = duration_seconds(r.get("time")) or t
                reports.append((rt, r))
                fixed_flags.append(baseline != "rolling")
                if r.get("audit_error"):
                    problems.append({"kind": "audit-error", "time": rt,
                                     "message": f"vulnerability audit failed: {r['audit_error']}"})
                if r.get("status") == "alert":
                    alert_reports.append({"time": rt} | _alert_counts(r))
            case "error":
                problems.append({"kind": "error", "time": t, "message": str(e.get("message", ""))})

    # the net change
    f = _Fold()
    fixed = bool(reports) and all(fixed_flags)
    fixed_extra: dict[str, list] = {}
    if fixed:
        f.report(reports[-1][1], reports[-1][0])
        fixed_extra = _fixed_transients(reports)
    else:
        for t, r in reports:
            f.report(r, t)

    packages, pkg_transient = f.packages.net()
    o_add, o_rem, o_tr = f.origins.net()
    s_add, s_rem, s_tr = f.sites.net()
    h_add, h_rem, h_tr = f.hooks.net()
    v_new, v_res, v_tr = f.vulns.net()
    x_new, x_res, x_tr = f.violations.net()

    def vuln_new(tr: _Track) -> dict:
        # the latest details, with the first source seen
        return _with_times(tr, tr.last_item | {"source": tr.first_item.get("source")})

    transient = {
        "packages": pkg_transient,
        "origins": [_with_times(tr, tr.first_item) for tr in o_tr],
        "sites": [_with_times(tr, tr.first_item) for tr in s_tr],
        "hooks": [_with_times(tr, tr.first_item) for tr in h_tr],
        "vulns": [_with_times(tr, tr.first_item if tr.first_change == "added" else tr.last_item)
                  | {"what": "fixed within the period" if tr.first_change == "added"
                     else "resolved then reintroduced"} for tr in v_tr],
        "violations": [_with_times(tr, tr.first_item) for tr in x_tr],
    }
    for cat, rows in fixed_extra.items():
        for row in rows:
            item = row["item"]
            if cat == "packages":
                pkg = item.get("to") or item.get("from") or {}
                transient["packages"].append({
                    "ecosystem": item.get("ecosystem"), "site": item.get("site"),
                    "key": pkg.get("key"), "name": pkg.get("name", pkg.get("key")),
                    "first": row["first"], "last": row["last"],
                    "what": f"{row['change']}, then back to the baseline",
                    "versions": [_version(item.get("from")), _version(item.get("to"))],
                    "steps": None})
            else:
                transient[cat].append(item | {"first": row["first"], "last": row["last"]}
                                      | ({"what": "fixed within the period"} if cat == "vulns" else {}))

    # missing scans
    if period:
        threshold = 2 * period + 60
        points = [start, *sorted(scan_times), end]
        for a, b in zip(points, points[1:]):
            if b - a > threshold:
                problems.append({"kind": "no-scan", "time": a, "until": b,
                                 "message": f"no scan for {_span(b - a)}"})
    problems.sort(key=lambda p: (p["time"], p["kind"]))

    new_vulns = sorted((vuln_new(tr) for tr in v_new),
                       key=lambda v: (-(v.get("score") or -1), _sort_key(*_vuln_key(v))))
    statuses = {r.get("status") for _, r in reports}
    status = ("alert" if "alert" in statuses else
              "changed" if "changed" in statuses else "unchanged")

    d = {
        "version": DIGEST_VERSION,
        "start": start,
        "end": end,
        "system": system,
        "baseline": baseline,
        "status": status,
        "reports": len(reports),
        "scans": len(scan_times),
        "starts": starts,
        "alert_reports": alert_reports,
        "packages": packages,
        "origins": {"added": [_with_times(tr, tr.last_item) for tr in o_add],
                    "removed": [_with_times(tr, tr.last_item) for tr in o_rem]},
        "sites": {"added": [_with_times(tr, tr.last_item) for tr in s_add],
                  "removed": [_with_times(tr, tr.last_item) for tr in s_rem]},
        "hooks": {"added": [_with_times(tr, tr.last_item) for tr in h_add],
                  "removed": [_with_times(tr, tr.last_item) for tr in h_rem]},
        "vulns": {"new": new_vulns,
                  "resolved": [_with_times(tr, tr.last_item) for tr in v_res]},
        "violations": {"new": [_with_times(tr, tr.last_item) for tr in x_new],
                       "resolved": [_with_times(tr, tr.last_item) for tr in x_res]},
        "transient": transient,
        "problems": problems,
        "latest_scan": None if last_scan is None else {
            "time": _t(last_scan), "origins": last_scan.get("origins"),
            "sites": last_scan.get("sites"), "packages": last_scan.get("packages"),
            "counts": last_scan.get("counts") or {}},
    }
    d["counts"] = counts(d)
    return d


def _span(seconds: float) -> str:
    m = int(seconds // 60)
    return f"{m // 60}h {m % 60:02d}m" if m >= 60 else f"{m}m"


def counts(d: dict) -> dict:
    """Headline numbers: the subject line, the Overview tab, whether anything happened."""
    pk = d["packages"]
    c = {
        "new_vulns": len(d["vulns"]["new"]),
        "new_hooks": len(d["hooks"]["added"]),
        "downgrades": sum(1 for p in pk if p["change"] == "downgraded"),
        "new_violations": len(d["violations"]["new"]),
        "package_changes": len(pk),
        "changes": (len(pk) + sum(len(d[k][x]) for k in ("origins", "sites")
                                  for x in ("added", "removed"))),
        "resolved_vulns": len(d["vulns"]["resolved"]),
        "removed_hooks": len(d["hooks"]["removed"]),
        "resolved_violations": len(d["violations"]["resolved"]),
        "transient": sum(len(v) for v in d["transient"].values()),
        "problems": len(d["problems"]),
        "alert_reports": len(d["alert_reports"]),
    }
    c["eventful"] = bool(d["status"] != "unchanged" or c["problems"] or c["transient"]
                         or c["changes"] or c["resolved_vulns"])
    return c


#-------------------------------------------------------------------------------
# the pending period, from the store

def last_digest_end(state: dict) -> float | None:
    """When the last digest's period ended (state.json `digest.last_end`)."""
    dg = state.get("digest") if isinstance(state.get("digest"), dict) else {}
    end = dg.get("last_end")
    return end if isinstance(end, (int, float)) else None


def pending_window(state: dict, first_entry_time: float | None, now: float) -> tuple[float, float]:
    """From the last digest's end (state.json), else the first stored entry, to now."""
    start = last_digest_end(state)
    if start is None:
        start = first_entry_time
    return (now if start is None else min(start, now)), now
