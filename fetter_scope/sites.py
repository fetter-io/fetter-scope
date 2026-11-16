"""Open vulnerabilities per site, across all history: what the Sites tab shows.

fetter reports a vulnerability once, as new, and again only when it is resolved (rolling
baseline), so the open set is new minus resolved over every report, not one digest period. The
`Inventory` folds `start` and `report` events into that set, plus the sites known from report
changes, and is saved as `sites.json` in the home so it outlives `events/` retention.

Folding is idempotent: a report at or before `through` (the last report applied) is skipped, so
the saved inventory can be topped up from stored events, and the TUI and the runtime can share one.
"""
import json
import logging
import os
import statistics
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from fetter_scope.events import duration_seconds

log = logging.getLogger(__name__)

SCHEMA = 1
CRITICAL = 9.0
HIGH = 7.0
UNNAMED = "(site not named)"     # a finding from fetter 5.0.0, which names no sites


def _score(v: dict) -> float | None:
    s = v.get("score")
    return float(s) if isinstance(s, (int, float)) and not isinstance(s, bool) else None


def vuln_key(v: dict) -> str:
    """One open vulnerability: ecosystem, package key, version and ID (a site holds a version)."""
    pkg = v.get("package") or {}
    return "\0".join(str(x) for x in (pkg.get("ecosystem", ""), pkg.get("key", pkg.get("name", "")),
                                      pkg.get("version", ""), v.get("id", "")))


def site_key(ecosystem: str, path: str) -> str:
    return f"{ecosystem}\0{path}"


def _sites(v: dict) -> list[str]:
    return sorted({s for s in v.get("sites") or [] if isinstance(s, str) and s})


@dataclass
class Inventory:
    vulns: dict[str, dict] = field(default_factory=dict)   # vuln_key → finding, with first, last
    sites: dict[str, dict] = field(default_factory=dict)   # site_key → {ecosystem, path, changed}
    through: float | None = None                           # the last report applied
    baseline: str = "rolling"

    # folding ----------------------------------------------------------------------

    def apply(self, e: dict | None) -> bool:
        """Fold one fetter event; returns whether it changed anything."""
        if not isinstance(e, dict) or e.get("source") == "fetter-scope":
            return False
        if e.get("event") == "start":
            b = e.get("baseline")
            self.baseline = b if isinstance(b, str) and b else "rolling"
            return False
        if e.get("event") != "report" or not isinstance(e.get("report"), dict):
            return False
        r = e["report"]
        t = duration_seconds(r.get("time")) or duration_seconds(e.get("time"))
        if t is None or (self.through is not None and t <= self.through):
            return False
        self.through = t
        self._changes(r.get("changes") or {}, t)
        new = [v for v in r.get("new_vulns") or [] if isinstance(v, dict)]
        # the whole set, so it replaces ours: a report establishing a baseline (no baseline_time:
        # every vulnerability is `existing`), or any report against a fixed baseline; not when
        # the audit failed, as its findings are then incomplete
        whole = r.get("baseline_time") is None or self.baseline != "rolling"
        if whole and not r.get("audit_error"):
            keep = {vuln_key(n) for n in new}
            self.vulns = {k: v for k, v in self.vulns.items() if k in keep}
        for v in new:
            k = vuln_key(v)
            first = (self.vulns.get(k) or {}).get("first", t)
            self.vulns[k] = {**v, "sites": _sites(v), "first": first, "last": t}
        for v in r.get("resolved_vulns") or []:
            if isinstance(v, dict):
                self.vulns.pop(vuln_key(v), None)
        return True

    def _changes(self, ch: dict, t: float) -> None:
        def touch(eco: str, path: str) -> None:
            if path:
                s = self.sites.setdefault(site_key(eco, path),
                                          {"ecosystem": eco, "path": path, "changed": t})
                s["changed"] = t
        for c in ch.get("packages") or []:
            touch(c.get("ecosystem", ""), c.get("site", ""))
        for c in ch.get("hooks") or []:
            touch(c.get("ecosystem", ""), c.get("site", ""))
        for c in ch.get("sites") or []:
            eco, path = c.get("ecosystem", ""), c.get("path", "")
            if c.get("change") == "removed":
                self.sites.pop(site_key(eco, path), None)
            else:
                touch(eco, path)

    def apply_all(self, events: Iterable[dict | None]) -> None:
        for e in events:
            self.apply(e)

    # persistence ------------------------------------------------------------------

    def to_json(self) -> dict:
        return {"schema": SCHEMA, "through": self.through, "baseline": self.baseline,
                "vulns": [self.vulns[k] for k in sorted(self.vulns)],
                "sites": [self.sites[k] for k in sorted(self.sites)]}

    @classmethod
    def from_json(cls, d: dict) -> "Inventory":
        inv = cls()
        if not isinstance(d, dict) or d.get("schema") != SCHEMA:
            return inv
        inv.through = d["through"] if isinstance(d.get("through"), (int, float)) else None
        inv.baseline = d.get("baseline") if isinstance(d.get("baseline"), str) else "rolling"
        inv.vulns = {vuln_key(v): v for v in d.get("vulns") or [] if isinstance(v, dict)}
        inv.sites = {site_key(s.get("ecosystem", ""), s.get("path", "")): s
                     for s in d.get("sites") or [] if isinstance(s, dict) and s.get("path")}
        return inv

    @classmethod
    def load(cls, path: Path) -> "Inventory":
        """The saved inventory, or an empty one (an unreadable file is logged, then rebuilt)."""
        try:
            return cls.from_json(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as e:
            log.warning("ignoring unreadable %s: %s", path, e)
            return cls()

    def save(self, path: Path) -> None:
        fd, tmp = tempfile.mkstemp(prefix=".sites-", suffix=".json", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.to_json(), f, sort_keys=True)
                f.write("\n")
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def open_inventory(store) -> Inventory:
    """The home's saved inventory, topped up from stored events after it (all retained events
    when there is none)."""
    inv = Inventory.load(store.home.sites)
    inv.apply_all(p.event for p in store.iter_entries(since=inv.through))
    return inv


# per-site summary -----------------------------------------------------------------------

@dataclass(frozen=True)
class SiteRow:
    key: str
    ecosystem: str
    path: str
    vulns: tuple[dict, ...]       # open findings at the site, highest CVSS first
    changed: float | None         # the latest report changing the site

    @property
    def scores(self) -> list[float]:
        return [s for v in self.vulns if (s := _score(v)) is not None]

    @property
    def open(self) -> int:
        return len(self.vulns)

    @property
    def max(self) -> float | None:
        return max(self.scores, default=None)

    @property
    def median(self) -> float | None:
        return statistics.median(self.scores) if self.scores else None

    @property
    def critical(self) -> int:
        return sum(s >= CRITICAL for s in self.scores)

    @property
    def high(self) -> int:
        return sum(HIGH <= s < CRITICAL for s in self.scores)

    @property
    def unscored(self) -> int:
        return self.open - len(self.scores)

    @property
    def packages(self) -> int:
        return len({((v.get("package") or {}).get("key"), (v.get("package") or {}).get("version"))
                    for v in self.vulns})


def site_rows(inv: Inventory) -> list[SiteRow]:
    """One row per site with an open vulnerability or a change on record; highest CVSS max
    first, then most open, then path."""
    at: dict[str, list[dict]] = {}
    for v in inv.vulns.values():
        eco = (v.get("package") or {}).get("ecosystem", "")
        for path in v.get("sites") or [UNNAMED]:
            at.setdefault(site_key(eco, path), []).append(v)
    rows = []
    for k in set(at) | set(inv.sites):
        eco, _, path = k.partition("\0")
        vulns = sorted(at.get(k, []), key=lambda v: (-(_score(v) or -1.0), v.get("id", "")))
        rows.append(SiteRow(k, eco, path, tuple(vulns), (inv.sites.get(k) or {}).get("changed")))
    rows.sort(key=lambda r: (-(r.max if r.max is not None else -1.0), -r.open, r.path, r.ecosystem))
    return rows
