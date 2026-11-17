"""The Textual app: a header, and tabs for Overview, Alerts, Changes, Live, Vulnerabilities,
Hooks, Mail and Log.

In launch mode the app drives a `Runtime` (supervisor, event log, mail); in attach mode it follows
a stream file or an `events/` directory and has no control channel. Either way every entry goes
through `Model.add`, and views are refreshed from the model on a timer, only when it changed
and only for the visible tab.

Keys: 1–8 switch tabs; `s` rescans and `r` reports now (launch mode); `m` sends the digest (after
a report, in launch mode); `p` previews its HTML in a browser; `c` copies the selected row's
package, ID or hook, `u` its URL; `l` reloads mail settings; `/` filters the current tab
(`key:value` words match a column, other words any column; Escape clears); `t` switches Changes
between the folded digest view and every report; `e` focuses the ecosystem selector (a row of
checkboxes above the Alerts, Changes, Live, Vulnerabilities and Hooks tables, one selection for
all of them; `o` there shows only the focused ecosystem); Enter opens a row's detail; `q` quits,
stopping fetter first. Column headers sort (again to reverse, a third time for the original order).
"""
import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import time
import webbrowser
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Checkbox, DataTable, Footer, Input, Label, Sparkline, Static,
                             TabbedContent, TabPane)

from fetter_scope import render
from fetter_scope.digest import last_digest_end
from fetter_scope.events import Parsed, summary
from fetter_scope.model import AlertItem, Model, digest_change_rows, matches
from fetter_scope.render import plural
from fetter_scope.sites import CRITICAL, HIGH, UNNAMED, SiteRow, site_rows
from fetter_scope.store import Store

TABS = ("overview", "alerts", "changes", "live", "vulns", "sites", "hooks", "mail", "log")
ECO_TABS = ("alerts", "changes", "live", "vulns", "hooks")   # with the ecosystem selector
ALL = "*"                                                    # the selector's "all" checkbox
REFRESH = 0.5          # seconds between view refreshes (only when the model changed)
DIGEST_EVERY = 10.0    # seconds between recomputing the pending digest while entries arrive
MAIL_REPORT_WAIT = 120  # `m`: seconds to wait for fetter's report before sending anyway
BAD_LOG = {"error", "protocol-error", "supervisor-error", "stdout"}
TYPE_STYLE = {"vuln": "bold red", "hook": "bold red", "downgrade": "red", "violation": "red"}
KIND_STYLE = {"downgraded": "red", "removed": "yellow", "added": "green", "new": "bold red",
              "resolved": "green", "transient": "yellow"}

open_browser = webbrowser.open          # replaced in tests


def hhmm(t: float | None, seconds: bool = False) -> str:
    if t is None:
        return "—"
    fmt = "%m-%d %H:%M:%S" if seconds else "%m-%d %H:%M"
    return time.strftime(fmt, time.localtime(t))


def ago(t: float | None, now: float) -> str:
    if t is None:
        return "—"
    d = int(now - t)
    if d < 0:
        return f"in {_dur(-d)}"
    return f"{_dur(d)} ago"


def _dur(s: int) -> str:
    if s < 90:
        return f"{s}s"
    if s < 5400:
        return f"{s // 60}m"
    if s < 2 * 86400:
        return f"{s // 3600}h {s % 3600 // 60:02d}m"
    return f"{s // 86400}d"


def badge(text: str, style: str) -> Text:
    return Text(f" {text} ", style=style)


#-------------------------------------------------------------------------------
# tables: fill, sort

# columns that can be long are given a width (cells are cut to it); the rest fit their content
WIDTHS = {"Detail": 44, "Site": 32, "Path": 64, "Entry": 110, "Summary": 48, "Content": 44, "Subject": 60,
          "Error": 40}

# a row: (key, cells, sort values); a sort value of None falls back to the cell's text
Row = tuple[str, list, list | None]


def _sort_value(row: Row, col: int):
    _, cells, values = row
    v = values[col] if values is not None and col < len(values) else None
    if v is None:
        cell = cells[col]
        v = cell.plain if isinstance(cell, Text) else str(cell)
    return None if v in ("", "—") else v


def ordered(rows: list[Row], sort: tuple[int, bool] | None) -> list[Row]:
    """Rows sorted by (column, descending); numbers before text, empty values last either way,
    ties in the original order."""
    if sort is None:
        return rows
    col, descending = sort
    valued = [(r, _sort_value(r, col)) for r in rows]
    have = [x for x in valued if x[1] is not None]
    have.sort(key=lambda x: (0, x[1], "") if isinstance(x[1], (int, float))
              else (1, 0, str(x[1]).lower()), reverse=descending)
    return [r for r, _ in have] + [r for r, v in valued if v is None]


def next_sort(current: tuple[int, bool] | None, col: int) -> tuple[int, bool] | None:
    """Ascending, then descending, then the original order; a new column starts ascending."""
    if current is None or current[0] != col:
        return (col, False)
    return (col, True) if not current[1] else None


def fill(table: DataTable, columns: list[str], rows: list[Row],
         sort: tuple[int, bool] | None = None) -> None:
    """Refill a table in sort order, keeping the cursor on the same row key when it is still
    there. The header marks the sorted column."""
    keep = None
    if table.row_count:
        try:
            keep = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:      # noqa: BLE001 - no cursor yet
            keep = None
    signature = (tuple(columns), sort)
    if getattr(table, "_signature", None) != signature:
        table.clear(columns=True)
        for i, c in enumerate(columns):
            mark = "" if sort is None or sort[0] != i else (" ▼" if sort[1] else " ▲")
            table.add_column(c + mark, key=c, width=WIDTHS.get(c))
        table._signature = signature
    else:
        table.clear()
    rows = ordered(rows, sort)
    keys, seen = [], set()
    for key, cells, _ in rows:
        unique, n = key, 1
        while unique in seen:              # never let a repeated key crash the app
            n += 1
            unique = f"{key}#{n}"
        seen.add(unique)
        keys.append(unique)
        table.add_row(*cells, key=unique)
    if keep in keys:
        table.move_cursor(row=keys.index(keep))


#-------------------------------------------------------------------------------
# clipboard

# (environment variable that must be set, command); OSC 52 is always sent as well
CLIPBOARD_TOOLS = (("WAYLAND_DISPLAY", ("wl-copy",)),
                   ("DISPLAY", ("xclip", "-selection", "clipboard")),
                   ("DISPLAY", ("xsel", "--clipboard", "--input")),
                   ("", ("pbcopy",)))


def system_copy(text: str) -> str | None:
    """Copy with the first available system tool; its name, or None."""
    for env, cmd in CLIPBOARD_TOOLS:
        if (env and not os.environ.get(env)) or (cmd[0] == "pbcopy" and sys.platform != "darwin"):
            continue
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(cmd, input=text.encode(), timeout=2, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return cmd[0]
        except (OSError, subprocess.SubprocessError):
            continue
    return None


#-------------------------------------------------------------------------------
# detail

def alert_detail(item: AlertItem, model: Model) -> Text:
    out = Text()

    def line(label: str, value, style: str = "") -> None:
        if value in (None, ""):
            return
        out.append(f"{label:<10}", style="dim")
        out.append(f"{value}\n", style=style)

    d = item.data
    out.append(f"{item.type.upper()}  ", style=TYPE_STYLE.get(item.type, "bold"))
    out.append(f"{item.subject}\n\n", style="bold")
    line("reported", hhmm(item.time, seconds=True))
    line("ecosystem", item.ecosystem)
    if item.type == "vuln":
        pkg = d.get("package") or {}
        line("id", d.get("id"), "bold")
        line("score", f"{d['score']:g}" if isinstance(d.get("score"), (int, float)) else "")
        line("severity", d.get("severity"))
        line("source", {"introduced": "introduced (the package was added or changed)",
                        "published": "published (a new advisory for an unchanged package)",
                        "existing": "existing (no earlier audit to compare to)"}
             .get(d.get("source"), d.get("source")))
        line("status", d.get("what"))
        line("package", f"{pkg.get('name')} {pkg.get('version')}  {pkg.get('purl', '')}".strip())
        line("url", d.get("url"), "underline")
        # fetter 5.1.0 names the sites; for findings recorded before it, only package changes do
        sites = [s for s in d.get("sites") or [] if isinstance(s, str)] or sorted(
            {c.site for c in model.changes
             if c.ecosystem == pkg.get("ecosystem") and c.name == pkg.get("name")})
        line("sites", "\n          ".join(sites) if sites else
             "not in the stream: the package has not changed since the baseline "
             "(recorded by a fetter before 5.1.0, which did not name a finding's sites)")
        if d.get("summary"):
            out.append("\n" + d["summary"] + "\n")
        out.append("\nc copies the ID, u the URL", style="dim")
    elif item.type == "hook":
        line("change", d.get("change"))
        line("site", item.site)
        out.append("\nThe hook's content, shown verbatim (never run):\n\n", style="dim")
        out.append((d.get("hook") or {}).get("detail", "") + "\n", style="on grey11")
    elif item.type == "downgrade":
        line("site", item.site)
        line("from", (d.get("from") or {}).get("version"))
        line("to", (d.get("to") or {}).get("version"), "red")
    elif item.type == "violation":
        line("package", d.get("package"))
        line("requires", d.get("dependency"))
        line("explain", d.get("explain"), "bold")
        line("sites", "\n          ".join(d.get("sites") or []))
    return out


def score_style(score: float | None) -> str:
    if score is None:
        return ""
    return "bold red" if score >= CRITICAL else "red" if score >= HIGH else "yellow" if score >= 4 else ""


def site_detail(row: SiteRow) -> Text:
    out = Text()
    out.append("SITE  ", style="bold")
    out.append(f"{row.path}\n\n", style="bold")
    for label, value in (("ecosystem", row.ecosystem),
                         ("open", f"{plural(row.open, 'vulnerability')} in "
                                  f"{plural(row.packages, 'package')}"),
                         ("CVSS", "" if row.max is None else
                          f"max {row.max:g}, median {row.median:g}; {row.critical} critical, "
                          f"{row.high} high, {row.unscored} unscored"),
                         ("changed", hhmm(row.changed, seconds=True) if row.changed else
                          "no change on record")):
        if value:
            out.append(f"{label:<10}", style="dim")
            out.append(f"{value}\n")
    if row.path == UNNAMED:
        out.append("\nFindings recorded by a fetter before 5.1.0, which did not name sites. To have "
                   "them named, stop fetter-scope, remove fetter's rolling baseline "
                   "(monitor_diff_v1_*.json in fetter's cache directory) and start again: the next "
                   "report re-establishes it, listing every existing vulnerability with its "
                   "sites.\n", style="dim")
    for v in row.vulns:
        pkg = v.get("package") or {}
        s = v.get("score")
        out.append("\n")
        out.append(f"{s:>4g}  " if isinstance(s, (int, float)) else "   –  ",
                   style=score_style(s if isinstance(s, (int, float)) else None))
        out.append(f"{v.get('id', '?')}", style="bold")
        out.append(f"  {pkg.get('name', '?')} {pkg.get('version', '')}  ")
        out.append(f"since {hhmm(v.get('first'))}\n", style="dim")
        if v.get("summary"):
            out.append(f"      {v['summary']}\n")
        if v.get("url"):
            out.append(f"      {v['url']}\n", style="underline")
    out.append("\nc copies the path", style="dim")
    return out


class Detail(ModalScreen):
    """A row's detail; `c` and `u` copy its ID (or package) and URL."""
    BINDINGS = [Binding("escape,q,enter", "dismiss", "Close"),
                Binding("c", "copy", "Copy"), Binding("u", "copy_url", "Copy URL")]
    DEFAULT_CSS = """
    Detail { align: center middle; }
    Detail > VerticalScroll { width: 90%; height: auto; max-height: 80%; border: round $accent;
        background: $surface; padding: 1 2; }
    """

    def __init__(self, text: Text, copy: tuple[str, str] = ("", "")):
        super().__init__()
        self.text = text
        self.copy = copy

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(self.text, id="detail")

    def action_copy(self) -> None:
        self.app.copy_text(self.copy[0])

    def action_copy_url(self) -> None:
        self.app.copy_text(self.copy[1], "URL")


AlertDetail = Detail      # the name milestone 5 used


class EcoBox(Checkbox):
    """A checkbox marked ● when on and ○ when off (Textual's marks only change colour), with no
    box: Textual's half-block edges draw a dark sliver beside a round mark."""
    ON, OFF = "●", "○"
    BUTTON_LEFT = BUTTON_RIGHT = ""
    DEFAULT_CSS = """
    EcoBox > .toggle--button { background: transparent; color: $text-muted; }
    EcoBox.-on > .toggle--button { background: transparent; color: $text-success; }
    EcoBox.-textual-compact:focus > .toggle--button {
        background: $block-cursor-background; color: $block-cursor-foreground; }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mark()

    def _mark(self) -> None:
        # a space before the mark, so the focus highlight wraps it as the label's padding does
        self.BUTTON_INNER = " " + (self.ON if self.value else self.OFF)

    def watch_value(self) -> None:
        self._mark()
        super().watch_value()


class EcoBar(Horizontal):
    """A row of ecosystem checkboxes above a tab's table. The selection is the app's, shared by
    every tab that has one; each bar counts its own tab's rows per ecosystem.

    Left and right move between the boxes, space or Enter toggles one, `o` shows only the
    focused ecosystem, and Down or Escape returns to the table."""
    BINDINGS = [Binding("left", "move(-1)", show=False), Binding("right", "move(1)", show=False),
                Binding("o", "only", "Only this"),
                Binding("down,escape", "leave", "Table", show=False)]
    DEFAULT_CSS = """
    EcoBar { height: 1; padding: 0 1; }
    EcoBar > Label { color: $text-muted; margin-right: 1; }
    EcoBar > Checkbox { margin-right: 1; }
    EcoBar > Checkbox.-textual-compact:focus { border: none !important; }
    """

    def __init__(self, tab: str):
        super().__init__(id=f"{tab}-ecos")
        self.tab = tab
        self.names: list[str] = []          # the boxes, in order: ALL, then ecosystems

    def show(self, ecos: list[str], counts: dict[str, int], hidden: set[str]) -> None:
        """Offer `ecos` (rebuilding the boxes only when the list changes) and check the shown."""
        names = [ALL] + ecos

        def label(n: str) -> Text:
            if n == ALL:
                return Text("all")
            return Text.assemble(n, " ", (str(counts.get(n, 0)), "dim"))

        def value(n: str) -> bool:
            return not hidden if n == ALL else n not in hidden

        if names != self.names:
            self.names = names
            self.remove_children()
            self.mount(Label("ecosystems"), *[EcoBox(label(n), value(n), name=n, compact=True)
                                              for n in names])
            return
        for box in self.query(Checkbox):
            box.label = label(box.name)
            if box.value != value(box.name):
                with box.prevent(Checkbox.Changed):
                    box.value = value(box.name)

    def boxes(self) -> list[Checkbox]:
        return list(self.query(Checkbox))

    def action_move(self, step: int) -> None:
        boxes = self.boxes()
        at = next((i for i, b in enumerate(boxes) if b.has_focus), 0)
        if boxes:
            boxes[max(0, min(len(boxes) - 1, at + step))].focus()

    def action_only(self) -> None:
        focused = next((b for b in self.boxes() if b.has_focus), None)
        if focused is not None:
            self.app.only_ecosystem(None if focused.name == ALL else focused.name)

    def action_leave(self) -> None:
        if (table := self.app._table(self.tab)) is not None:
            table.focus()


#-------------------------------------------------------------------------------

class ScopeApp(App):
    TITLE = "fetter-scope"
    CSS = """
    Screen { overflow: hidden; }
    #header { height: auto; padding: 0 1; background: $panel; }
    #tabs { height: 1fr; }
    #tabs > ContentSwitcher { height: 1fr; }
    TabPane { height: 1fr; padding: 0; }
    #filter { dock: bottom; display: none; }
    #filter.shown { display: block; }
    #overview-body { padding: 0 1; }
    #ecosystems { height: auto; max-height: 16; margin: 1 0; }
    #spark { height: 3; margin: 0 0 1 0; }
    .note { color: $text-muted; }
    .heading { text-style: bold; margin: 1 0 0 0; }
    #changes-mode, #vulns-mode, #sites-mode, #hooks-mode { padding: 0 1; }
    /* one row, always: the ecosystem selector under it stays at the same height on every tab */
    .mode { height: 1; padding: 0 1; text-wrap: nowrap; text-overflow: ellipsis; }
    #mail-body { padding: 0 1; }
    #mail-table { height: auto; max-height: 10; }
    #mail-preview-box { height: 1fr; border: round $panel; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "rescan", "Rescan"),
        Binding("r", "report", "Report"),
        Binding("m", "mail", "Mail digest"),
        Binding("p", "preview", "Preview"),
        Binding("c", "copy", "Copy"),
        Binding("u", "copy_url", "Copy URL", show=False),
        Binding("l", "reload", "Reload", show=False),
        Binding("slash", "filter", "Filter"),
        Binding("t", "toggle_changes", "Folded/all", show=False),
        Binding("e", "ecosystems", "Ecosystems"),
    ] + [Binding(str(i), f"tab('{tab}')", tab, show=False) for i, tab in enumerate(TABS, 1)]

    def __init__(self, model: Model, *, runtime=None, follow_path: Path | None = None,
                 store: Store | None = None, mailer=None, period: int | None = None,
                 baseline: str = "rolling", fetter_version: str = "", theme: str = "",
                 load_config: Callable | None = None,
                 now: Callable[[], float] = time.time):
        super().__init__()
        self.model = model
        self.runtime = runtime
        self.follow_path = follow_path
        self.store = store
        self.mailer = mailer
        self.period = period
        self.baseline = baseline
        self.fetter_version = fetter_version
        self.theme_name = theme
        self.load_config = load_config
        self.now = now
        self.filters: dict[str, str] = {}
        self.sorts: dict[str, tuple[int, bool] | None] = {"vulns": (1, True)}   # CVSS, high first
        self.targets: dict[str, dict[str, tuple[str, str]]] = {}   # tab → row key → (copy, url)
        self.details: dict[str, dict[str, AlertItem | SiteRow]] = {}   # tab → row key → detail item
        self.folded = True
        self.hidden_ecos: set[str] = set()       # unchecked in the ecosystem selector (all tabs)
        self.busy = ""                           # "sending digest…" while `m` runs
        self._seen: dict[str, tuple] = {}        # tab → what it was last drawn from
        self._digest: dict | None = None
        self._digest_at = (-1, 0.0)              # (model version, time) of the digest
        self._worker = None
        self._stop_follow = asyncio.Event()
        self._quitting = False

    # layout ---------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(id="header")
        with TabbedContent(id="tabs", initial="overview"):
            with TabPane("Overview", id="overview"):
                with Vertical(id="overview-body"):
                    yield Static(id="ov-report")
                    yield DataTable(id="ecosystems", cursor_type="none", zebra_stripes=True)
                    yield Static("packages over this session", classes="note")
                    yield Sparkline([], id="spark")
                    yield Static(id="ov-digest")
            with TabPane("Alerts", id="alerts"):
                yield Static(id="alerts-mode", classes="mode")
                yield EcoBar("alerts")
                yield DataTable(id="alerts-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Changes", id="changes"):
                yield Static(id="changes-mode", classes="mode")
                yield EcoBar("changes")
                yield DataTable(id="changes-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Live", id="live"):
                yield Static(id="live-mode", classes="mode")
                yield EcoBar("live")
                yield DataTable(id="live-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Vulnerabilities", id="vulns"):
                yield Static(id="vulns-mode", classes="mode")
                yield EcoBar("vulns")
                yield DataTable(id="vulns-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Sites", id="sites"):
                yield Static(id="sites-mode")
                yield DataTable(id="sites-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Hooks", id="hooks"):
                yield Static(id="hooks-mode", classes="mode")
                yield EcoBar("hooks")
                yield DataTable(id="hooks-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Mail", id="mail"):
                with Vertical(id="mail-body"):
                    yield Static(id="mail-info")
                    yield Static("Sent", classes="heading")
                    yield DataTable(id="mail-table", cursor_type="row", zebra_stripes=True)
                    yield Static(id="mail-preview-title", classes="heading")
                    with VerticalScroll(id="mail-preview-box"):
                        yield Static(id="mail-preview")
            with TabPane("Log", id="log"):
                yield DataTable(id="log-table", cursor_type="row", zebra_stripes=True)
        yield Input(placeholder="filter: words, or key:value (Escape clears)", id="filter",
                    disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        if self.theme_name:
            try:
                self.theme = self.theme_name
            except Exception:      # noqa: BLE001 - an unknown theme keeps the default
                pass
        self.set_interval(REFRESH, self.refresh_views)
        self.refresh_views(force=True)
        if self.runtime is not None:
            self._worker = self.run_worker(self.runtime.run(), exit_on_error=False)
        elif self.follow_path is not None:
            from fetter_scope.supervisor import follow
            self._worker = self.run_worker(
                follow(self.follow_path, self.ingest, stop=self._stop_follow), exit_on_error=False)

    def ingest(self, p: Parsed) -> None:
        self.model.add(p)

    # navigation, filter, sort ----------------------------------------------------

    @property
    def active_tab(self) -> str:
        return self.query_one("#tabs", TabbedContent).active or "overview"

    def action_tab(self, tab: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab

    def _show_filter(self, shown: bool) -> Input:
        """The filter box is disabled while hidden, so it never takes keys meant for the app."""
        box = self.query_one("#filter", Input)
        box.set_class(shown, "shown")
        box.disabled = not shown
        return box

    def action_filter(self) -> None:
        box = self._show_filter(True)
        box.value = self.filters.get(self.active_tab, "")
        box.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.filters[self.active_tab] = event.value
            self.refresh_views(force=True)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter" and (table := self._table(self.active_tab)) is not None:
            table.focus()

    def on_key(self, event) -> None:
        box = self.query_one("#filter", Input)
        if event.key == "escape" and box.has_class("shown"):
            box.value = ""
            self.filters.pop(self.active_tab, None)
            self._show_filter(False)
            if (table := self._table(self.active_tab)) is not None:
                table.focus()
            self.refresh_views(force=True)
            event.stop()

    def action_toggle_changes(self) -> None:
        self.folded = not self.folded
        self.action_tab("changes")
        self.refresh_views(force=True)

    def action_ecosystems(self) -> None:
        """Focus the ecosystem selector of the current tab (the first box after "all")."""
        if self.active_tab not in ECO_TABS:
            self.notify("no ecosystem selector on this tab", severity="warning")
            return
        boxes = self.query_one(f"#{self.active_tab}-ecos", EcoBar).boxes()
        if boxes:
            boxes[1 if len(boxes) > 1 else 0].focus()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        name = event.checkbox.name
        if name == ALL:
            bar = event.checkbox.parent
            self.hidden_ecos = set() if event.value else set(getattr(bar, "names", [])[1:])
        elif event.value:
            self.hidden_ecos.discard(name)
        else:
            self.hidden_ecos.add(name)
        self.refresh_views(force=True)

    def only_ecosystem(self, eco: str | None) -> None:
        """Show only `eco` (None: all) in every tab with the selector."""
        names = self.query_one(f"#{self.active_tab}-ecos", EcoBar).names[1:]
        self.hidden_ecos = set() if eco is None else {n for n in names if n != eco}
        self.refresh_views(force=True)

    def _eco_pass(self, counts: dict[str, int], eco: str) -> bool:
        """Count a row (one that passed the text filter) for its ecosystem, and whether the
        selector shows it; a row naming no ecosystem is always shown."""
        if not eco:
            return True
        counts[eco] = counts.get(eco, 0) + 1
        return eco not in self.hidden_ecos

    def _show_ecos(self, tab: str, counts: dict[str, int]) -> None:
        ecos = sorted(set(self.model.ecosystems()) | set(counts) | self.hidden_ecos)
        self.query_one(f"#{tab}-ecos", EcoBar).show(ecos, counts, self.hidden_ecos)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        query = self.filters.get(self.active_tab, "")
        box = self._show_filter(bool(query))
        with box.prevent(Input.Changed):
            box.value = query
        if (table := self._table(self.active_tab)) is not None:
            table.focus()
        self.refresh_views(force=True)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        tab = (event.data_table.id or "").removesuffix("-table")
        if tab in TABS:
            self.sorts[tab] = next_sort(self.sorts.get(tab), event.column_index)
            self.refresh_views(force=True)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tab = (event.data_table.id or "").removesuffix("-table")
        key = event.row_key.value
        item = self.details.get(tab, {}).get(key)
        if item is not None:
            text = site_detail(item) if isinstance(item, SiteRow) else alert_detail(item, self.model)
            self.push_screen(Detail(text,
                                    self.targets.get(tab, {}).get(key, ("", ""))))

    # copy -------------------------------------------------------------------------

    def copy_text(self, text: str, what: str = "") -> None:
        if not text:
            self.notify(f"nothing to copy{' (no ' + what + ')' if what else ''}", severity="warning")
            return
        self.copy_to_clipboard(text)                 # OSC 52, through the terminal
        tool = system_copy(text)
        self.notify(f"copied {text}" + (f" (and {tool})" if tool else ""), timeout=3)

    def _selected(self) -> tuple[str, str]:
        tab = self.active_tab
        table = self._table(tab)
        if table is None or not table.row_count:
            return "", ""
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:          # noqa: BLE001 - no cursor
            return "", ""
        return self.targets.get(tab, {}).get(key, ("", ""))

    def action_copy(self) -> None:
        self.copy_text(self._selected()[0])

    def action_copy_url(self) -> None:
        self.copy_text(self._selected()[1], "URL")

    # control channel and mail -------------------------------------------------------

    def _no_control(self) -> bool:
        if self.runtime is None:
            self.notify("attached: read-only, no control channel", severity="warning")
            return True
        return False

    def action_rescan(self) -> None:
        if not self._no_control():
            self.run_worker(self._request("scan"))

    def action_report(self) -> None:
        if not self._no_control():
            self.run_worker(self._request("report"))

    async def _request(self, command: str) -> dict | None:
        sup = self.runtime.supervisor
        if sup.pending is not None:
            self.notify(f"{sup.pending.command} requested; waiting for fetter", timeout=3)
            return None
        future = await sup.request(command)
        if future is None:
            self.notify("fetter is not running", severity="error")
            return None
        ack = await future
        if ack is None:
            self.notify(f"no answer from fetter to {command}", severity="warning")
        return ack

    def action_mail(self) -> None:
        if self.mailer is None:
            self.notify("attached: mail is sent by the fetter-scope running fetter",
                        severity="warning")
            return
        if missing := self.mailer.cfg.mail_missing:
            self.notify(f"mail not configured: {', '.join(missing)} not set", severity="error")
            return
        if self.busy:
            return
        self.run_worker(self._send_digest())

    async def _send_digest(self) -> None:
        self.busy = "sending digest…"
        try:
            sup = self.runtime.supervisor if self.runtime is not None else None
            if sup is not None and sup.can_request:
                self.busy = "reporting before the digest…"
                future = await sup.request("report")
                if future is not None:
                    try:
                        await asyncio.wait_for(asyncio.shield(future), MAIL_REPORT_WAIT)
                    except TimeoutError:
                        pass
                self.busy = "sending digest…"
            result = await self.mailer.send_digest(force=True)
            self._digest_at = (-1, 0.0)              # the period moved on
            if result is not None and result.ok:
                self.notify("digest sent to " + ", ".join(self.mailer.cfg.credentials.email_to))
            else:
                self.notify(f"digest not sent: {result.error if result else 'nothing to send'}",
                            severity="error")
        finally:
            self.busy = ""
            self.refresh_views(force=True)

    def action_preview(self) -> None:
        d = self.pending_digest()
        if d is None:
            self.notify("nothing recorded yet", severity="warning")
            return
        html, _, _ = render.fit(d, attached=False)
        fd, path = tempfile.mkstemp(prefix="fetter-scope-digest-", suffix=".html")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(html)
        open_browser(Path(path).as_uri())
        self.notify(f"preview: {path}", timeout=6)

    def action_reload(self) -> None:
        if self.load_config is None or self.mailer is None:
            self.notify("nothing to reload when attached", severity="warning")
            return
        cfg = self.load_config()
        if cfg.errors:
            self.notify(f"config.toml has errors; settings kept: {cfg.errors[0]}", severity="error")
            return
        old = self.mailer.cfg
        self.mailer.cfg = replace(old, mail=cfg.mail, credentials=cfg.credentials)
        self._digest_at = (-1, 0.0)
        self.notify("reloaded mail settings")
        if cfg.fetter != old.fetter:
            self.notify("fetter settings changed: restart fetter-scope to apply them",
                        severity="warning")
        self.refresh_views(force=True)

    async def action_quit(self) -> None:
        if self._quitting:
            if self.runtime is not None:
                await self.runtime.supervisor.stop()     # a second q: terminate now
            return
        self._quitting = True
        if self.runtime is not None and self._worker is not None:
            self.notify("stopping fetter… (q again to terminate it)")
            await self.runtime.supervisor.stop()
            await self._worker.wait()
        else:
            self._stop_follow.set()
        self.exit()

    # data ---------------------------------------------------------------------------

    def _table(self, tab: str) -> DataTable | None:
        try:
            return self.query_one(f"#{tab}-table", DataTable)
        except Exception:          # noqa: BLE001 - overview has none
            return None

    def digest_start(self) -> float | None:
        if self.store is not None:
            start = last_digest_end(self.store.read_state())
            if start is not None:
                return start
        return next((t for e in self.model.entries
                     if (t := (e.get("time") or {}).get("secs")) is not None), None)

    def pending_digest(self) -> dict | None:
        """The digest `m` would send now (cached briefly while entries arrive)."""
        now = self.now()
        version, at = self._digest_at
        if self._digest is not None and (version == self.model.version or now - at < DIGEST_EVERY):
            return self._digest
        if self.mailer is not None:
            d = self.mailer.pending()                # marks what alert mails covered
            self._digest = d if d["reports"] or d["scans"] or self.model.entries else None
        else:
            start = self.digest_start()
            self._digest = None if start is None else self.model.digest(
                min(start, now), now + 1e-6, self.period, self.baseline)
        self._digest_at = (self.model.version, now)
        return self._digest

    def mailed(self, t: float) -> str:
        if self.store is None:
            return ""
        windows = (self.store.read_state().get("alerts") or {}).get("windows") or []
        if any(a <= t < b for a, b in windows):
            return "mailed"
        return "" if self.mailer is None or not self.mailer.enabled else "no"

    # views --------------------------------------------------------------------------

    def refresh_views(self, force: bool = False) -> None:
        self.update_header()
        tab = self.active_tab
        drawn_from = (self.model.version, self._digest_at)
        if not force and self._seen.get(tab) == drawn_from:
            return
        getattr(self, f"draw_{tab}")()
        self._seen[tab] = (self.model.version, self._digest_at)

    def update_header(self) -> None:
        m, now = self.model, self.now()
        sysd = m.system
        host = sysd.get("hostname") or "?"
        line1 = Text()
        line1.append(f"fetter · {host}", style="bold")
        os_ = " ".join(x for x in (sysd.get("os_name"), sysd.get("os_version"),
                                   sysd.get("architecture")) if x)
        if os_:
            line1.append(f" ({os_})")
        line1.append(f" · fetter {self.fetter_version or '?'} · schema 1")
        if m.newer:
            line1.append(f" · newer fetter (schema {m.newer}): some fields may be ignored",
                         style="yellow")
        base = (m.start or {}).get("baseline") or self.baseline
        line1.append(" · rolling baseline" if base == "rolling" else f" · baseline {base}")

        line2 = Text()
        d = self.pending_digest()
        status = d["status"] if d else "unchanged"
        line2.append_text(badge("ALERT", "bold white on red") if status == "alert" else
                          badge(status, "black on yellow" if status == "changed" else "black on green"))
        if m.fetter not in ("running", "attached"):
            line2.append(" ")
            line2.append_text(badge(f"fetter {m.fetter}", "bold white on dark_red"))
        elif m.fetter == "attached":
            line2.append(" ")
            line2.append_text(badge("attached: read-only", "black on cyan"))
        last = (m.last_scan or {}).get("time", {}).get("secs") if m.last_scan else None
        line2.append(f"  last scan {ago(last, now)}")
        if m.fetter != "attached":
            line2.append(f" · next scan {ago(m.next_scan_at(), now)}")
        if self.mailer is not None:
            nd = self.mailer.next_digest_at() if self.mailer.enabled else None
            line2.append(f" · next digest {hhmm(nd)}" if nd else "")
            status = self.mailer.status().split(" (")[0].split(":")[0]   # details: Mail tab
            line2.append(f" · {status}",
                         style="" if status in ("mail ok", "mail disabled") else "yellow")
        pending = self.runtime.supervisor.pending if self.runtime is not None else None
        activity = self.busy or ({"scan": "rescanning…", "report": "reporting…"}
                                 .get(pending.command, "") if pending is not None else "")
        if activity:
            line2.append(f"  {activity}", style="bold cyan")
        self.query_one("#header", Static).update(Text("\n").join([line1, line2]))

    def draw_overview(self) -> None:
        m = self.model
        dropped = set(m.dropped_to_zero())
        rows = []
        for eco, c in sorted(m.counts().items()):
            style = "bold red" if eco in dropped else ""
            rows.append((eco, [Text(eco, style=style),
                               Text(str(c.get("origins", 0)), justify="right"),
                               Text(str(c.get("sites", 0)), justify="right"),
                               Text(str(c.get("packages", 0)), justify="right", style=style)],
                         None))
        fill(self.query_one("#ecosystems", DataTable),
             ["Ecosystem", "Origins", "Sites", "Packages"], rows)
        self.query_one("#spark", Sparkline).data = [n for _, n, _ in m.scans[-200:]] or [0]

        rep = Text()
        latest = m.latest_report()
        if latest is None:
            rep.append("No report yet.", style="dim")
        else:
            t, r = latest
            rep.append(f"Latest report {hhmm(t, True)}: ", style="bold")
            st = r.get("status", "?")
            rep.append(st.upper() if st == "alert" else st, style="bold red" if st == "alert" else "")
            ch = r.get("changes") or {}
            parts = [f"{len(r.get(k) or [])} {w}" for k, w in (
                ("new_vulns", "new vulns"), ("resolved_vulns", "resolved vulns"),
                ("new_violations", "new violations"))] + \
                [f"{len(ch.get(k) or [])} {k}" for k in ("packages", "sites", "origins", "hooks")]
            rep.append(" · " + ", ".join(parts))
            if r.get("audit_error"):
                rep.append(f"\naudit error: {r['audit_error']}", style="yellow")
        if dropped:
            rep.append(f"\n{', '.join(sorted(dropped))} dropped to zero packages: "
                       "more likely a scan problem than removals", style="bold red")
        self.query_one("#ov-report", Static).update(rep)

        dg = Text()
        d = self.pending_digest()
        if d is None:
            dg.append("Pending digest: nothing recorded yet.", style="dim")
        else:
            c = d["counts"]
            dg.append(f"Pending digest since {hhmm(d['start'])}: ", style="bold")
            bits = [plural(c[k], w) for k, w in (
                ("new_vulns", "new vuln"), ("new_hooks", "new hook"), ("downgrades", "downgrade"),
                ("new_violations", "new violation"), ("changes", "change"),
                ("transient", "transient item"), ("problems", "problem"),
                ("resolved_vulns", "resolved vuln")) if c[k]]
            dg.append(", ".join(bits) if bits else "nothing changed")
            dg.append(f"  ({plural(d['reports'], 'report')}, {plural(d['scans'], 'scan')})",
                      style="dim")
        self.query_one("#ov-digest", Static).update(dg)

    def _draw(self, tab: str, columns: list[str], rows: list[Row],
              targets: dict[str, tuple[str, str]],
              details: dict[str, AlertItem | SiteRow] | None = None):
        self.targets[tab] = targets
        self.details[tab] = details or {}
        fill(self.query_one(f"#{tab}-table", DataTable), columns, rows, self.sorts.get(tab))

    def draw_alerts(self) -> None:
        q = self.filters.get("alerts", "")
        rows, targets, details, counts = [], {}, {}, {}
        for a in reversed(self.model.alerts):
            fields = {"type": a.type, "eco": a.ecosystem, "name": a.subject, "site": a.site,
                      "detail": a.detail}
            if q and not matches(q, fields):
                continue
            if not self._eco_pass(counts, a.ecosystem):
                continue
            rows.append((a.key, [Text(a.type, style=TYPE_STYLE.get(a.type, "")), a.ecosystem,
                                 Text(a.subject, style="bold"), a.site, a.detail,
                                 hhmm(a.time), self.mailed(a.time)],
                         [None] * 5 + [a.time, None]))
            if a.type == "vuln":
                targets[a.key] = (a.data.get("id", ""), a.data.get("url", ""))
            else:
                targets[a.key] = (a.subject, "")
            details[a.key] = a
        m = self.model
        self.query_one("#alerts-mode", Static).update(Text(
            (f"{plural(len(m.alerts), 'alert')} in {plural(len(m.reports), 'report')}, newest "
             "first: new vulnerabilities, hooks, downgrades and violations. Enter shows one.") if m.reports else "No report yet: alerts appear with fetter's reports.",
            style="dim"))
        self._show_ecos("alerts", counts)
        self._draw("alerts", ["Type", "Ecosystem", "Package / hook", "Site", "Detail",
                              "Reported", "Mailed"], rows, targets, details)

    def draw_changes(self) -> None:
        q = self.filters.get("changes", "")
        base = (self.model.start or {}).get("baseline") or self.baseline
        since = "the last report" if base == "rolling" else "the baseline"   # what a report compares with
        if self.folded:
            d = self.pending_digest()
            items = list(reversed(digest_change_rows(d))) if d else []
            mode = (f"Package changes since {since}, folded since the last "
                    f"digest ({hhmm(d['start'])}): net change per package"
                    if d else f"Package changes since {since}: nothing recorded yet")
        else:
            items = list(reversed(self.model.changes))
            mode = f"Package changes since {since}, every report, newest first"
        self.query_one("#changes-mode", Static).update(Text(mode + "  (t switches)", style="dim"))
        rows, targets, counts = [], {}, {}
        for c in items:
            fields = {"kind": c.change, "eco": c.ecosystem, "site": c.site, "name": c.name,
                      "from": c.frm, "to": c.to}
            if q and not matches(q, fields):
                continue
            if not self._eco_pass(counts, c.ecosystem):
                continue
            rows.append((c.key, [Text(c.change, style=KIND_STYLE.get(c.change, "")), c.ecosystem,
                                 c.site, Text(c.name, style="bold"), c.frm, c.to, hhmm(c.time)],
                         [None] * 6 + [c.time]))
            targets[c.key] = (c.name, "")
        self._show_ecos("changes", counts)
        self._draw("changes", ["Kind", "Ecosystem", "Site", "Name", "From", "To", "Reported"],
                   rows, targets)

    def draw_live(self) -> None:
        q = self.filters.get("live", "")
        rows, targets, counts = [], {}, {}
        for r in self.model.live:
            fields = {"trigger": r.trigger, "what": r.what, "kind": r.change, "eco": r.ecosystem,
                      "name": r.name, "detail": r.detail}
            if q and not matches(q, fields):
                continue
            if not self._eco_pass(counts, r.ecosystem):
                continue
            rows.append((r.key, [hhmm(r.time, True), r.trigger, r.what,
                                 Text(r.change, style=KIND_STYLE.get(r.change, "")), r.ecosystem,
                                 Text(r.name, style="bold"), r.detail], [r.time] + [None] * 6))
            targets[r.key] = (r.name, "")
        last = self.model.last_scan
        self.query_one("#live-mode", Static).update(Text(
            (f"Changes since the previous scan, newest first (latest scan "
             f"{hhmm((last.get('time') or {}).get('secs'), seconds=True)}): packages, sites, "
             "origins and hooks, ahead of fetter's next report.")
            if last else "No scan yet: each scan's changes appear here as they arrive.", style="dim"))
        self._show_ecos("live", counts)
        self._draw("live", ["Time", "Trigger", "What", "Change", "Ecosystem", "Name", "Detail"],
                   rows, targets)

    def draw_vulns(self) -> None:
        q = self.filters.get("vulns", "")
        d = self.pending_digest()
        self.query_one("#vulns-mode", Static).update(Text(
            f"Since the last digest ({hhmm(d['start'])}): new, resolved and transient" if d
            else "Since the last digest: nothing recorded yet", style="dim"))
        rows, targets, details, counts = [], {}, {}, {}
        groups = [] if d is None else [("new", d["vulns"]["new"]),
                                       ("resolved", d["vulns"]["resolved"]),
                                       ("transient", d["transient"]["vulns"])]
        for status, items in groups:
            for v in items:
                pkg = v.get("package") or {}
                key = f"{status}:{pkg.get('ecosystem')}:{pkg.get('key')}:{v.get('id')}"
                score = v.get("score") if isinstance(v.get("score"), (int, float)) else None
                fields = {"id": v.get("id", ""), "status": status, "eco": pkg.get("ecosystem", ""),
                          "name": pkg.get("name", ""), "source": v.get("source", ""),
                          "summary": v.get("summary", "")}
                if q and not matches(q, fields):
                    continue
                if not self._eco_pass(counts, pkg.get("ecosystem", "")):
                    continue
                mailed = "mailed" if v.get("mailed") else ""
                rows.append((key, [Text(v.get("id", "?"), style="bold"),
                                   Text("" if score is None else f"{score:g}", justify="right"),
                                   Text(status, style=KIND_STYLE.get(status, "")),
                                   pkg.get("ecosystem", ""),
                                   f"{pkg.get('name', '?')} {pkg.get('version', '')}".strip(),
                                   v.get("source", ""), mailed, v.get("summary", ""),
                                   hhmm(v.get("first"))],
                             [None, score] + [None] * 6 + [v.get("first")]))
                targets[key] = (v.get("id", ""), v.get("url", ""))
                details[key] = AlertItem(key, "vuln", pkg.get("ecosystem", ""),
                                         f"{pkg.get('name', '?')} {pkg.get('version', '')}".strip(),
                                         "", "", v.get("first") or 0, v, score)
        self._show_ecos("vulns", counts)
        self._draw("vulns", ["ID", "CVSS", "Status", "Ecosystem", "Package", "Source", "Mailed",
                             "Summary", "Seen"], rows, targets, details)

    def draw_sites(self) -> None:
        q = self.filters.get("sites", "")
        inv = self.model.inventory
        all_rows = site_rows(inv)
        need = sum(1 for r in all_rows if r.open)
        self.query_one("#sites-mode", Static).update(Text(
            (f"Open vulnerabilities per site, over all history (through {hhmm(inv.through)}): "
             f"{plural(need, 'site')} with open vulnerabilities, of {len(all_rows)}. "
             "Enter lists a site's vulnerabilities." if inv.through is not None
             else "No report yet: open vulnerabilities per site appear after fetter's first report."),
            style="dim"))
        rows, targets, details = [], {}, {}
        for r in all_rows:
            fields = {"site": r.path, "eco": r.ecosystem,
                      "id": " ".join(v.get("id", "") for v in r.vulns),
                      "name": " ".join((v.get("package") or {}).get("name", "") for v in r.vulns)}
            if q and not matches(q, fields):
                continue
            mx, med = r.max, r.median
            rows.append((r.key, [
                Text("" if mx is None else f"{mx:g}", style=score_style(mx), justify="right"),
                Text("" if med is None else f"{med:g}", justify="right"),
                Text(str(r.open), style="bold" if r.open else "dim", justify="right"),
                Text(str(r.critical) if r.critical else "", style="bold red", justify="right"),
                Text(str(r.high) if r.high else "", style="red", justify="right"),
                Text(str(r.unscored) if r.unscored else "", justify="right"),
                Text(str(r.packages) if r.packages else "", justify="right"),
                r.ecosystem, Text(r.path, style="dim italic" if r.path == UNNAMED else ""),
                hhmm(r.changed)],
                [mx, med, r.open, r.critical, r.high, r.unscored, r.packages, None, None,
                 r.changed]))
            targets[r.key] = (r.path, "")
            details[r.key] = r
        self._draw("sites", ["Max", "Median", "Open", "Critical", "High", "Unscored", "Packages",
                             "Ecosystem", "Path", "Changed"], rows, targets, details)

    def draw_hooks(self) -> None:
        q = self.filters.get("hooks", "")
        d = self.pending_digest()
        self.query_one("#hooks-mode", Static).update(Text(
            (f"Since the last digest ({hhmm(d['start'])}). " if d else "")
            + "A hook runs without being invoked; Enter shows its content, which is never run.",
            style="dim"))
        rows, targets, details, counts = [], {}, {}, {}
        groups = [] if d is None else [("added", d["hooks"]["added"]),
                                       ("removed", d["hooks"]["removed"]),
                                       ("transient", d["transient"]["hooks"])]
        for status, items in groups:
            for h in items:
                hook = h.get("hook") or {}
                key = f"{status}:{h.get('site')}:{hook.get('name')}:{hash(hook.get('detail'))}"
                first = (hook.get("detail") or "").strip().splitlines()
                fields = {"change": status, "eco": h.get("ecosystem", ""), "site": h.get("site", ""),
                          "name": hook.get("name", ""), "content": hook.get("detail", "")}
                if q and not matches(q, fields):
                    continue
                if not self._eco_pass(counts, h.get("ecosystem", "")):
                    continue
                rows.append((key, [Text(status, style="bold red" if status == "added" else
                                        KIND_STYLE.get(status, "")),
                                   h.get("ecosystem", ""), h.get("site", ""),
                                   Text(hook.get("name", "?"), style="bold"),
                                   first[0] if first else "", hhmm(h.get("first"))],
                             [None] * 5 + [h.get("first")]))
                targets[key] = (hook.get("name", ""), "")
                details[key] = AlertItem(key, "hook", h.get("ecosystem", ""), hook.get("name", "?"),
                                         h.get("site", ""), "", h.get("first") or 0,
                                         h | {"change": status})
        self._show_ecos("hooks", counts)
        self._draw("hooks", ["Change", "Ecosystem", "Site", "Hook", "Content", "Seen"], rows,
                   targets, details)

    def draw_mail(self) -> None:
        info = Text()
        mailer = self.mailer
        if mailer is None:
            info.append("Attached: mail is sent by the fetter-scope that runs fetter.", style="dim")
            self.query_one("#mail-info", Static).update(info)
            self.query_one("#mail-preview-title", Static).update("Pending digest")
            d = self.pending_digest()
            self.query_one("#mail-preview", Static).update(render.text(d, attached=False) if d else "")
            self._draw("mail", ["Time", "Kind", "Result", "Subject", "Error"], [], {})
            return
        cfg = mailer.cfg
        m = cfg.mail
        state = mailer.store.read_state()
        dg, al = state.get("digest") or {}, state.get("alerts") or {}

        def row(label: str, value: str, style: str = "") -> None:
            info.append(f"{label:<14}", style="dim")
            info.append(value + "\n", style=style)

        row("status", mailer.status(), "" if mailer.status() in ("mail ok", "mail disabled") else "yellow")
        row("transport", m.transport)
        row("to", ", ".join(cfg.credentials.email_to) or "(REPORT_EMAIL_TO not set)")
        every = f"every {m.every // 86400}d" if m.every % 86400 == 0 else f"every {m.every // 3600}h"
        row("schedule", f"{every} at {m.at[0]:02d}:{m.at[1]:02d}"
                        + (f" on {m.weekday}" if m.weekday else "")
                        + (", even when unchanged" if m.send_unchanged else ""))
        row("next digest", hhmm(mailer.next_digest_at()) if m.enabled else "—")
        row("last digest", "none yet" if not dg.get("last_result") else
            f"{hhmm(dg.get('last_at'))}: {dg['last_result']}"
            + (f" ({dg['last_error']})" if dg.get("last_error") else ""),
            "red" if dg.get("failures") else "")
        row("alerts", f"{m.alerts}, at most one mail every {m.alert_min_interval // 60}m"
                      + ("; one pending" if al.get("pending") else "")
                      + (f"; last sent {hhmm(al['last_sent'])}" if al.get("last_sent") else ""))
        self.query_one("#mail-info", Static).update(info)

        history = state.get("mail_history") or []
        rows = []
        for i, h in enumerate(reversed(history)):
            bad = h.get("result") == "failed"
            rows.append((str(i), [hhmm(h.get("time"), True), h.get("kind", ""),
                                  Text(h.get("result", ""), style="bold red" if bad else ""),
                                  h.get("subject", ""), h.get("error", "")],
                         [h.get("time")] + [None] * 4))
        self._draw("mail", ["Time", "Kind", "Result", "Subject", "Error"], rows,
                   {k: (cells[3], "") for k, cells, _ in rows})

        d = self.pending_digest()
        self.query_one("#mail-preview-title", Static).update(
            "Pending digest (p opens its HTML; m sends it now)" if d else "Pending digest")
        self.query_one("#mail-preview", Static).update(
            Text(f"Subject: {render.subject(d, m.subject_prefix)}\n\n" + render.text(d))
            if d else Text("Nothing recorded yet.", style="dim"))

    def draw_log(self) -> None:
        q = self.filters.get("log", "")
        rows, targets = [], {}
        for i, p in enumerate(self.model.log):
            text = summary(p)
            fields = {"event": p.kind, "text": text}
            if q and not matches(q, fields):
                continue
            e = p.event or {}
            bad = (p.kind in BAD_LOG or p.event is None
                   or (p.kind == "fetter-exit" and not e.get("expected"))
                   or (p.kind == "mail" and e.get("result") == "failed"))
            t = (e.get("time") or {}).get("secs")
            rows.append((str(i), [hhmm(t, True), Text(p.kind, style="bold red" if bad else "dim"),
                                  Text(text, style="red" if bad else "")], [t, None, None]))
            targets[str(i)] = (text, "")
        table = self.query_one("#log-table", DataTable)
        at_end = table.row_count == 0 or table.cursor_row >= table.row_count - 1
        self._draw("log", ["Time", "Event", "Entry"], rows, targets)
        if at_end and rows and self.sorts.get("log") is None:
            table.move_cursor(row=len(rows) - 1)
