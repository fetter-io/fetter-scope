"""Plain-file storage under the home directory: `events/`, `state.json`.

- `events/YYYY-MM-DD.jsonl` (local date of receipt): every fetter event line as received, and
  fetter-scope's own entries (`events.own`), one JSON object per line, appended and flushed.
- `state.json`: small mutable state (the running fetter's pid; later digest and mail state),
  written to a temp file and renamed.

`mail/` is added with delivery (milestone 4).
"""
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import IO

from fetter_scope.events import Parsed, duration_seconds, parse_line
from fetter_scope.home import Home

log = logging.getLogger(__name__)

_DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")


class Store:
    def __init__(self, home: Home, now: Callable[[], float] = time.time):
        self.home = home
        self.now = now
        self._fh: IO[str] | None = None
        self._day: str = ""

    # events -------------------------------------------------------------------

    def append(self, p: Parsed) -> None:
        """Append one entry to today's file and flush it."""
        day = date.fromtimestamp(self.now()).isoformat()
        if day != self._day or self._fh is None:
            self.close()
            self.home.events.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.home.events / f"{day}.jsonl", "a", encoding="utf-8")
            self._day = day
        self._fh.write(p.line.replace("\n", " ") + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def event_files(self) -> list[Path]:
        """Daily files, oldest first."""
        if not self.home.events.is_dir():
            return []
        return sorted(p for p in self.home.events.iterdir() if _DAY_FILE.match(p.name))

    def iter_entries(self, since: float | None = None) -> Iterator[Parsed]:
        """Stored entries in order; with `since` (epoch seconds), those at or after it.

        An entry whose time cannot be read is kept, so nothing is silently dropped.
        """
        first_day = date.fromtimestamp(since).isoformat() if since is not None else ""
        for path in self.event_files():
            if path.stem < first_day:
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    p = parse_line(line)
                    if since is not None and p.event is not None:
                        t = duration_seconds(p.event.get("time"))
                        if t is not None and t < since:
                            continue
                    yield p

    def last_system(self) -> dict:
        """The `system` of the latest stored entry that has one (newest file first), or {}."""
        for path in reversed(self.event_files()):
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            for line in reversed(lines):
                p = parse_line(line)
                if p.event is not None and isinstance(p.event.get("system"), dict):
                    return p.event["system"]
        return {}

    def prune(self, retention_days: int) -> list[Path]:
        """Remove daily files older than `retention_days` (0 keeps all); returns those removed."""
        if retention_days <= 0:
            return []
        cutoff = (date.fromtimestamp(self.now()) - timedelta(days=retention_days)).isoformat()
        removed = []
        for path in self.event_files():
            if path.stem < cutoff:
                try:
                    path.unlink()
                    removed.append(path)
                except OSError as e:
                    log.warning("cannot remove %s: %s", path, e)
        return removed

    # state --------------------------------------------------------------------

    def read_state(self) -> dict:
        """state.json, or {} if missing or unreadable (an unreadable file is logged)."""
        try:
            data = json.loads(self.home.state.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            log.warning("ignoring unreadable %s: %s", self.home.state, e)
            return {}
        return data if isinstance(data, dict) else {}

    def write_state(self, state: dict) -> None:
        self.home.ensure()
        fd, tmp = tempfile.mkstemp(prefix=".state-", suffix=".json", dir=self.home.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, self.home.state)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def update_state(self, **changes) -> dict:
        """Set top-level keys (None removes one) and write; returns the new state."""
        state = self.read_state()
        for k, v in changes.items():
            if v is None:
                state.pop(k, None)
            else:
                state[k] = v
        self.write_state(state)
        return state
