# fetter-scope: Specification (preliminary)

A terminal app that runs `fetter monitor-diff`, reads its event stream, and shows what is changing on a system:
- packages, sites and origins;
- new vulnerabilities, including advisories newly published against packages that did not change;
- new hooks, downgrades and allow-list violations.

It also emails a digest at its own frequency, independent of how often fetter scans and reports, and can email alerts as they happen.

fetter does the scanning, diffing and evaluation; fetter-scope only launches, consumes, displays, accumulates and delivers. It is modeled on `../assistant-bom` and `../assistant-markets`, with the same packaging (uv, Python 3.14; the build backend is `uv_build`, not hatchling), TUI library (Textual), configuration style (`config.toml` read with `tomllib`, secrets in `.env`), plain-file storage, and Postmark delivery through `urllib`.

This document is preliminary: it fixes the scope and the contract with fetter, and leaves layout details to the first milestones.

**Principles**
- **fetter is the source of truth.** Every finding shown or mailed comes from a fetter event. fetter-scope never re-derives vulnerabilities, hooks or versions. It only folds reports together over time (see Digest).
- **The stream is the only interface.** fetter-scope reads `monitor-diff json` events and never fetter's cache or baseline files. Unknown events and fields are ignored, the rule fetter's own schema 1 readers follow.
- **No silent gaps.** A fetter crash, a failed scan, an audit fetter reports as unavailable, or a failed email is shown and recorded. None of them is ever shown as "unchanged".
- **Read-only toward the system.** fetter-scope never installs, removes or "accepts" anything except through fetter's own commands. For example, a fixed baseline is written by `fetter monitor-diff save`.
- **Local and private.** Reports contain user names, host names and paths. They go only to the configured recipient, and nothing is sent anywhere else.

## Picking this up

*Last updated 2026-11-16, after milestone 7 (service examples, README). Update this section at the end of every session; Milestones is the source of truth for progress.*

### Where we are

- **All milestones (1–8) are done.** Milestones 5, 6 and 8 were committed in `d4da057`.
- **Uncommitted**: milestone 7 (`examples/`, README, and the `dotenv` systemd credential in `config.py`), and the ecosystem selector (`EcoBar` in `tui.py`, `Model.ecosystems`; see Displays); check `git status`. The maintainer commits.
- **Service tested** 2026-11-16 in a Debian trixie container (systemd 257, Docker Desktop, aarch64) with fetter 5.1.0 built by cargo. These were confirmed:
  - the `--all-users` scan of another user's 0700 home;
  - the credential (token not in the environment);
  - `systemctl stop` (fetter-scope sends `stop`, fetter exits 3, which is a clean stop);
  - `attach` on the service's `events/`;
  - the three-exit stop under `Restart=`;
  - the read-only, no-exec and hidden paths, and `IPAddressDeny`;
  - `systemd-analyze security` 1.6.

  `SocketBindDeny` was not applied by that VM's kernel. In Docker, `LoadCredential` also needs `mount --make-rshared /` first, a container quirk and not part of the unit. Found while testing:
  - fetter does not create its `--cache-directory` (now made by `StateDirectory=`);
  - fetter runs the interpreters it discovers (see Open questions);
  - `ExecPaths=/home` is overridden by `ProtectHome=`'s mount, but paths below `/home` work.
- **fetter**: requires and installs 5.1.0 (`FETTER_VERSION`, `MIN_VERSION` in `fetter_bin.py`), whose vulnerability findings carry `sites`. 5.1.0 is on crates.io but **not yet on PyPI**, so `install-fetter` without a Rust toolchain fails until the wheel is published.
- **Health**: `uv run pytest` reports 260 passed (≈30 s; no test runs a real fetter, sends mail or uses the network). `ruff check` (0.17.5, with no `[tool.ruff]` in `pyproject.toml`, so the rule set depends on the machine) reports 54 findings, mostly import order, quoted annotations and unused `noqa`, plus 4 `ASYNC230` (a blocking `open` in async code) worth a look.
- **Verified on this machine** (full home scan, 7,336 packages): the Sites tab lists 102 sites with open vulnerabilities from 3,556 findings, 3,540 with sites. That needed fetter's 5.0.0 rolling baseline removed so the next report re-established it (see Displays, Sites); the old file is kept as `~/.cache/io.fetter/monitor_diff_v1_<hash>.json.bak-2026-11-16` and can be deleted. An OSV 503 during one report was handled as designed (no change to the open set; fetter kept its baseline's vulnerabilities).

### Code map

| Concern | Where |
|---|---|
| CLI: `tui`, `run [--headless]`, `attach`, `digest`, `check`, `install-fetter` | `fetter_scope/__main__.py` |
| fetter binary: resolve, version check, install (cargo, else PyPI wheel) | `fetter_scope/fetter_bin.py` |
| Event parsing, schema 1 TypedDicts, one-line summaries | `fetter_scope/events.py` |
| Launch, restart, control channel, attach; `Runtime` (store, mail, inventory per entry) | `fetter_scope/supervisor.py` |
| `events/`, `state.json`, retention | `fetter_scope/store.py`; paths in `fetter_scope/home.py` |
| Digest folding (pure) / HTML and text / delivery / schedule | `fetter_scope/{digest,render,delivery,scheduler}.py` |
| Open vulnerabilities per site (`Inventory`, `sites.json`, `site_rows`) | `fetter_scope/sites.py` |
| TUI model (no Textual) / Textual app, tabs, details, keys | `fetter_scope/model.py` / `fetter_scope/tui.py` |
| Fake fetter for supervisor and TUI tests; recorded streams | `tests/fake_fetter.py`; `tests/fixtures/streams/` |

### Next

1. **fetter: interpreters run by a privileged scan** (Open questions): the systemd unit forbids executing anything under homes, so venvs whose interpreter lives in a home are not scanned. A fetter change (site-packages from `pyvenv.cfg` and the layout without running the interpreter, or no inherited capabilities for what it runs) would lift that. It affects fetter-agent's unit too, which allows the execution.
2. **Lint**: add `[tool.ruff]` to `pyproject.toml` and clear its findings; check the `ASYNC230` ones in the supervisor and attach code.
3. **fetter: sites of hook-derived packages** (fetter SPEC, Known issues): `diff_report::package_sites` should fall back to the pre-commit config a derived package (e.g. `black` from `psf/black`) was mapped from; 16 findings here lack sites because of it. A fetter patch release; fetter-scope then only bumps `FETTER_VERSION`.
4. **Re-record the fixture streams** with fetter 5.1.0 (`tests/fixtures/streams/`, recorded under 5.0.0), so the fixtures carry `sites` and the TUI tests exercise them from real output rather than hand-built reports.
5. **Release check**: confirm the 5.1.0 wheel is on PyPI, then try `install-fetter --method pypi`.
6. **Open questions** below, notably transient changes between reports, net classification after folding, report acknowledgement, and control in attach mode.

## Contract with fetter

Requires fetter 5.1.0 or later (5.0.0 was the first release with `monitor-diff`, its per-ecosystem counts and its control channel; 5.1.0 adds the sites of each vulnerability finding, which the Sites tab needs). At start, fetter-scope runs `fetter --version` and refuses an older binary with a clear message.

**The fetter binary:** fetter-scope runs its own copy of fetter, not whatever `fetter` is on `PATH` (often an older PyPI install). fetter is not a Python dependency.
- The binary lives at `~/.fetter-scope/bin/fetter` (see Storage). fetter-scope pins the fetter version it installs (`FETTER_VERSION`, 5.1.0; 5.0.0 at first).
- `fetter-scope install-fetter [--method auto|cargo|pypi] [--force]` installs it:
  1. **cargo** (when `cargo` is on `PATH`): `cargo install fetter --version =FETTER_VERSION --locked --root ~/.fetter-scope`.
  2. **PyPI** (no Rust toolchain, or `--method pypi`): download the `fetter==FETTER_VERSION` wheel with `pip download --no-deps --only-binary :all:` and extract only its binary into `~/.fetter-scope/bin/`. Nothing is installed into the Python environment.
  The binary is installed to a temp directory, checked with `--version`, then moved into place. Re-running at the pinned version does nothing unless `--force`.
- `[fetter] binary` in `config.toml` overrides this with an explicit path. `PATH` is never searched.
- When the binary is missing, `check` says so and `tui`/`run` offer to install it; nothing is installed silently.

**Launch:** one long-running child process:
```
fetter <global args> monitor-diff --period P --report-period R [--report always]
       [--baseline FILE] [--bound FILE ...] [--cvss=N] --control stdin json
```
- stdout is read line by line, as JSON Lines.
- stdin is a pipe held open by fetter-scope for the control channel (below).
- stderr is captured into the event log as `stderr` lines. With `--log`, it becomes fetter's diagnostic log.

**Events** are fetter `monitor_diff::Event`, at schema 1. Each is a JSON object with `schema`, `event`, `time` (`{secs, nanos}`) and `system`.

| Event | Fields used | Use |
|---|---|---|
| `start` | `baseline` (`rolling` or a path), `baseline_time`, `period`, `report_period`, `ecosystems`, `control` | header; scan schedule; whether rescan keys are enabled |
| `scan` | `trigger` (`start`, `period`, `request`), `origins`, `sites`, `packages`, `counts` (per ecosystem: `{origins, sites, packages}`, as `fetter count`), `changes` (a `ScanDiff` since the previous scan) | heartbeat, counts history, live change feed; acknowledges a rescan request |
| `report` | `report`: a `DiffReport` (`status`, `baseline_time`, `time`, `changes`, `new_vulns`, `resolved_vulns`, `audit_error`, `new_violations`, `resolved_violations`) | alerts, digest input |
| `error` | `message` | shown in the event log; counted in the digest |

A line that is not JSON, or an event with a `schema` greater than 1, is kept in the raw log. Its known fields are used, and the header shows a "newer fetter" notice.

**Process lifecycle:**
- **Unexpected exit:** fetter-scope restarts fetter with exponential backoff (5 s doubling to 10 min) and records a `fetter-exit` entry. Three exits in a row with no `scan` event in between stop the restarts and raise a visible error.
- **Exit code 3:** fetter exits with 3 when its last report was an alert. In run-once mode (unused here) that is the alert signal; fetter 5.0.0 also does it after `stop` when the last report it evaluated was an alert, written or not (`monitor_diff_loop` returns that flag; observed recording `tests/fixtures/streams/changes.jsonl`). So an exit with 0 or 3 after fetter-scope wrote `stop` is a clean stop; any exit not preceded by `stop` is unexpected.
- **Stopping** (quit, or a configuration change that needs a restart): fetter-scope writes `stop`, waits up to 30 s for the process to exit (a scan in progress finishes first), then terminates it. A child killed mid-report does not advance the rolling baseline, so either way nothing is lost.

**Control channel:** fetter is launched with `--control stdin`, and fetter-scope writes commands to its stdin, one per line, UTF-8, ending in `\n`:

| Command | fetter's response | Used for |
|---|---|---|
| `scan` | scans now; a `scan` event with `trigger: "request"`. A report follows only if one is due by `--report-period`. | `s`: rescan now (the Live and Overview tabs update) |
| `report` | scans now and reports whether or not one is due: a `scan` event with `trigger: "request"`, then a `report` event (unless nothing changed and `--report change`); the report timer restarts | `r`: report now; before `m` sends a digest, so it includes the current state |
| `stop` | finishes the current scan or report, then exits with 0 (3 if the last report was an alert; see Exit code 3) | quit and restart |
| anything else | an `error` event (`Unknown control command: …`); fetter keeps running | logged as a protocol error (a fetter-scope bug, or a fetter too old for a command) |

Rules for the supervisor:
- **Commands are read only between scans.** A command sent during a scan waits until it ends, and each command runs its own scan. fetter-scope therefore keeps at most one request outstanding: after writing `scan` or `report`, it ignores further `s`/`r` presses (the footer shows "rescanning…") until a `scan` event with `trigger: "request"` arrives, or 10 minutes pass.
- **Acknowledgement is the next `request` scan event.** There is no request id; with one outstanding request, the next `request` scan answers it. A `report` request is complete at the following `report` event, or at that scan event if nothing changed and no report was written. The stream does not say which, so after the `request` scan fetter-scope waits for the report until the next event or 2 minutes, then takes the scan as the answer (see Open questions).
- **A closed stdin is not a stop.** If fetter-scope's end of the pipe closes (fetter-scope crashed), fetter keeps scanning on its period. fetter-scope's next start finds no child it owns and launches a new one, so a stray fetter could run alongside. To prevent this, fetter-scope records the child's pid in `state.json` and on start stops a recorded process that is still running fetter (`stop` is impossible without its stdin, so it is terminated).
- **Write failures** (a broken pipe) mean fetter has exited; the exit handling above applies.
- `--control` requires a period above 0, which fetter-scope always uses.

**Attach mode:** `fetter-scope attach FILE` follows a stream that fetter writes itself (`monitor-diff ... json -o FILE`, e.g. under launchd or systemd), without launching fetter. `FILE` may also be fetter-scope's own `events/` directory: its daily files are read in order and the newest is followed, moving on at midnight. The file is read from its start, then followed through appends, truncation and replacement. There is no control channel in this mode, so rescan and report-now are disabled. `attach --print` prints one line per entry instead of opening the TUI. (A file or socket control channel in fetter would enable them; `--control` takes a value so one can be added.)

## Configuration

`config.toml` is `~/.fetter-scope/config.toml` (see Storage), or `--config FILE`. fetter-scope may be installed into a user's site-packages, so configuration never lives beside the package. It is read with `tomllib` and never written. Every key is optional.

```toml
[fetter]
binary = ""                       # "" uses ~/.fetter-scope/bin/fetter; or an explicit path
args = []                         # global args, e.g. ["-E", "python,npm", "--root", "~/src"]
period = 300                      # seconds between scans
report_period = 300               # seconds between fetter reports (each advances fetter's rolling baseline); defaults to period
report = "change"                 # fetter's --report: "change", or "always" (a report every report period)
baseline = ""                     # a fixed baseline file from `fetter monitor-diff save`; "" is rolling
bound = ""                        # an allow list for validation; new violations are alerts
bound_options = []                # with bound: extra dependency groups
subset = false                    # with bound: fetter's --subset, --superset, --strict
superset = false
strict = false
cvss = 0                          # 0 is no filter

[mail]
enabled = false
transport = "postmark"            # or "smtp"
every = "1d"                      # digest frequency: "6h", "1d", "7d", ...
at = "07:00"                      # local time of day, when `every` is a whole number of days
weekday = ""                      # e.g. "mon", when `every` is "7d"
send_unchanged = false            # send a digest even when nothing happened (a heartbeat)
alerts = "immediate"              # "immediate" mails each alert report as it arrives; "digest" waits
alert_min_interval = "15m"        # at most one immediate alert mail per interval; later ones join the next
subject_prefix = "fetter"

[tui]
theme = ""                        # a Textual theme name
feed_limit = 2000                 # live change feed entries kept in memory

[store]
retention_days = 90               # events/ files older than this are removed; 0 keeps all
```

**Credentials** come from the environment, never from `config.toml`. Lowest precedence first: the `.env` beside `config.toml`; a systemd credential named `dotenv` in the same format (`$CREDENTIALS_DIRECTORY/dotenv`, from the service's `LoadCredential=`, so a root-only file can feed a `DynamicUser` service); then the process environment. The process environment is never modified, so secrets read from either file are not inherited by fetter. `check` prints which files it read:
- `REPORT_EMAIL_FROM` and `REPORT_EMAIL_TO` (comma-separated);
- for Postmark: `POSTMARK_SERVER_TOKEN`;
- for SMTP: `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_TLS` (`starttls` by default, or `ssl`).

If mail is enabled but not configured, the app shows "mail not configured" and keeps accumulating.

## Digest: folding reports over time

fetter compares each report with the last reported state, so a digest covering several reports has to combine them. `digest.fold(entries, start, end)` combines the period's stored entries (fetter's events and fetter-scope's own, since problems come from both) into one view. With a rolling baseline, reports are chained as below. With a fixed baseline (`--baseline FILE`), every report is against that baseline, so the last report is the net change and items in earlier reports but not the last are transient. A period that mixes both (a configuration change) is chained.

- **Packages**, keyed by `(ecosystem, site, key)`:
  - keep the earliest `from` and the latest `to`;
  - if they are equal, the change cancelled out; it is listed under **Transient**, e.g. "installed then removed between 02:10 and 02:40", because a short-lived package is itself a signal;
  - otherwise the kind is recomputed from the net change. Added then removed is transient; added then upgraded is added at the final version. Upgrade versus downgrade is taken from fetter's own classification: the last step's kind when it spans the same versions as the net change; otherwise the common kind when every step was an upgrade (or every one a downgrade), since ordering is transitive; otherwise `changed`. Python never re-implements version ordering. See Open questions.
- **Sites, origins and hooks:** net added or removed, by key; anything that cancelled out goes under Transient.
- **Vulnerabilities**, keyed by `(ecosystem, package key, id)`:
  - new and later resolved within the period is listed as **Transient**, "fixed within the period";
  - otherwise net new (with the first `source` seen) or net resolved.
- **Violations:** the same as vulnerabilities, keyed by the record.
- **Problems:** audit errors, `error` events, unexpected fetter exits, protocol and supervisor errors, and periods with no `scan` event for more than twice the scan period plus a minute (including stretches when fetter-scope was not running), all with times.
- **Status:** `alert` if any report in the period was an alert, even if it later cancelled out; otherwise `changed` or `unchanged`. The digest also lists each alert report it contains, with its time.

Folding is pure: event dicts in, a JSON-serializable digest dict out (stored with each sent digest). It is tested against recorded streams. A digest is *eventful*, and so sent without `send_unchanged`, if its status is not `unchanged` or it has changes, transient items, resolved vulnerabilities or problems.

## Displays (Textual)

**Header and summary line:**
- the system (host, OS), fetter version and schema, and the baseline (rolling, or the fixed file and its time);
- last scan, next scan, and the next digest;
- a status badge (`ALERT`, `changed`, `unchanged`, `fetter not running`).

**Tabs:**
- **Overview:**
  - per-ecosystem counts of origins, sites and packages from the latest `scan` event's `counts`, highlighting an ecosystem that dropped to zero (more likely a scan problem than removals), with a sparkline of packages over the session (from the stored scans);
  - the latest report's status and section counts;
  - the pending digest's counts.
- **Alerts:** one row per alert item, its type first: `vuln`, `hook`, `downgrade`, `violation`. Then ecosystem, package or site, detail, report time, and whether it has been mailed.
  - For a vulnerability, the detail is the ID, CVSS score, source and summary.
  - Enter opens a detail screen: the full summary, severity vector, OSV URL (with copy), and the sites holding the package. fetter 5.1.0 names them in the finding (`sites`), which the Alerts row also shows; for a finding stored from an earlier fetter they come from package changes only, so for a package unchanged since the baseline they are not known.
- **Changes:** every package change from reports, with the kind (added, removed, upgraded, downgraded, changed), ecosystem, site, name, from and to, and time.
  - Filters (`/`, per tab): `key:value` words match a column (e.g. `eco:npm kind:down site:proj`), other words match any column; all case-insensitive substrings.
  - A toggle switches between "since last digest" (the folded view) and "all reports".
- **Live:** the `scan` events' changes since the previous scan as they arrive, newest first. These come before fetter's next report, so the live view leads the report.
- **Vulnerabilities:** new, resolved and transient vulnerabilities for the pending digest period (marked when an alert mail already sent them), sortable by CVSS, with copy for the ID and URL and a detail screen (Enter).
- **Sites:** one row per site, so the sites that need attention show first. Columns: CVSS max, CVSS median, open vulnerabilities, critical (≥ 9.0) and high (7.0 to 9.0) counts, unscored count, affected packages, ecosystem, path, and the time of the site's latest change. Sorted by CVSS max, then open count, highest first; column headers re-sort; filterable (`site:`, `eco:`, `id:`, `name:`).
  - A vulnerability is counted once per site, package version and ID. The median and max are over the scored ones; unscored ones are counted apart, never treated as 0.
  - "Open" means reported new and not since resolved, over all history, not the digest period. It is kept by `sites.Inventory` and saved as `sites.json` (see Storage), so it outlives `events/` retention. With a fixed baseline each report replaces the set (see below); vulnerabilities present in the baseline itself are never reported, so they are not shown.
  - Sites named by package, hook or site changes are listed too, with zero counts, so a site that was cleaned up stays visible; a site reported removed is dropped. A site whose packages never changed and never had a vulnerability is not in the stream and is not listed.
  - Findings with no sites are grouped under "(site not named)": those stored from a fetter before 5.1.0, and (fetter 5.1.0) vulnerabilities in packages the audit derives from pre-commit hooks (see Open questions). A rolling baseline does not report them again, so after upgrading, remove fetter's rolling baseline (`monitor_diff_v1_*.json` in fetter's cache directory: `~/.cache/io.fetter` on Linux, `~/Library/Caches/io.fetter` on macOS) while fetter-scope is stopped. The next report re-establishes it (no `baseline_time`) and lists every existing vulnerability with its sites.
  - Such a report, and any report against a fixed baseline, is the whole set, so it replaces the inventory's open vulnerabilities (keeping each one's first-seen time); not when the report has an `audit_error`, since its findings are then incomplete. fetter, for its part, keeps the baseline's vulnerabilities through a failed audit (`monitor_diff.rs`), so the next good report compares against the right set; an OSV 503 on 2026-11-16 left both unchanged.
  - Verified 2026-11-16 on a full home scan: after removing the 5.0.0 baseline, the re-establishing report listed 3,556 vulnerabilities, 3,540 with sites, across 102 sites (the worst: a Python virtualenv with 813 open, CVSS max 10).
  - Enter opens the site's detail: its counts and its open vulnerabilities by CVSS, each with ID, package, first seen, summary and OSV URL; `c` copies the path.
- **Hooks:** added, removed and transient hooks for the pending digest period, with their full detail (Enter). A hook's content is code; it is shown verbatim and never run.
- **Mail:** status, transport and recipients (the address only, never credentials); the schedule and next digest time; the last digest's time and result (with its error); the alert mode and state; the history of sent and failed mails; and a preview of the pending digest (subject and text body).
- **Log:** raw events and fetter stderr, filterable by event type. Errors are highlighted.

**Ecosystem selector:** above the Alerts, Changes, Live, Vulnerabilities and Hooks tables, a row of checkboxes: `all`, then each ecosystem the session knows (packages in the latest scan, or named by a report or scan row), each with the number of the tab's rows in it (after the `/` filter). One selection applies to all five tabs; Overview, Sites, Mail and Log are not affected. Rows that name no ecosystem are always shown. The selection is kept for the session only. `e` focuses it; Left and Right move, space toggles, `o` shows only the focused ecosystem, and Down or Escape returns to the table.

**Keys:**

| Key | Action |
|---|---|
| `s` | rescan now (`scan` on the control channel; launch mode only) |
| `r` | report now (`report` on the control channel; launch mode only) |
| `m` | send the digest now (sends `report` first in launch mode, then sends the digest when that report or scan event arrives, or after 2 minutes) |
| `p` | preview the digest's HTML in a browser (a temp file) |
| `c` | copy the selected row's package, ID or hook name (OSC 52, plus the clipboard tool when present, as in assistant-bom); also in a detail screen |
| `u` | copy the selected row's URL (a vulnerability's OSV page) |
| `/` | filter the current tab; Escape clears |
| `t` | Changes: folded since the last digest, or every report |
| `e` | focus the ecosystem selector (Alerts, Changes, Live, Vulnerabilities, Hooks); there, `o` shows only the focused ecosystem |
| `1`–`9` | switch tabs (Overview, Alerts, Changes, Live, Vulnerabilities, Sites, Hooks, Mail, Log) |
| Enter, Escape | open and close a row's detail (alert, vulnerability, hook, site) |
| `l` | reload `config.toml` (mail settings and credentials only; a change to fetter settings is reported as needing a restart; a file with errors is not applied) |
| `q` | quit; fetter is stopped (`stop`, then terminated after 30 s; `q` again terminates it now) |

Column headers sort, as in assistant-bom: ascending, then descending, then the original order; numbers numerically and empty cells last. Vulnerabilities starts by CVSS, highest first. While `s`, `r` or `m` waits on fetter or the mail service, the header says so ("rescanning…", "reporting…", "sending digest…"); the UI stays responsive.

**Headless:** `fetter-scope run --headless` runs the same supervisor, storage and mail scheduler without the TUI, for a launchd or systemd service (`examples/`; setup in the README). SIGTERM stops fetter as `q` does (`stop`, then terminate after 30 s), so a service allows 45 s and signals only fetter-scope (`KillMode=mixed`). Exit 1 after the three-exit stop is retried by the service manager after 10 minutes, not at once.
  - **systemd** (`examples/systemd/fetter-scope.service`): a system service with a `DynamicUser`, and only `CAP_DAC_READ_SEARCH` (for `--all-users`).
    - Files: `/opt/fetter-scope` holds the install; `/etc/fetter-scope/config.toml` the configuration; `/var/lib/fetter-scope` the home, with fetter's `--cache-directory` (its rolling baseline) in `fetter/`. Mail secrets come as the `dotenv` credential.
    - Execution is allowed only in `/opt/fetter-scope`, `/usr/bin`, `/usr/local/bin` and the libraries, because fetter runs the interpreters it discovers and the capability is passed on to them. Trusted users' homes can be allowed by a drop-in.
    - The rest is the standard hardening: read-only system and homes, hidden secrets, syscall filter, no W+X memory, outbound network only.
  - **launchd** (`examples/launchd/io.fetter.fetter-scope.plist`): a per-user LaunchAgent with the usual `~/.fetter-scope`. It restarts on failure (throttled to 10 minutes), runs at background priority with umask 0077, and has a 45 s exit timeout. The TUI can then `attach` to the stored stream to view it. `fetter-scope`, `tui` and `run` without `--headless` open the TUI running fetter; it first replays the pending period from `events/`, so the tabs are not empty at start.

## Mail

- **Transport:** Postmark through `urllib` (as `assistant-bom/delivery.py`), or SMTP through `smtplib`. Both are stdlib; there is no mail dependency.
- **Subject:** `fetter <host> · ALERT · 3 new vulns · 1 hook · 1 downgrade · 42 changes`, with zero counts omitted, and `unchanged` for a heartbeat.
- **Body:** HTML with inline styles (no classes or SVG), plus a text alternative.
  - Section order: alerts first (new vulnerabilities by CVSS, new hooks, downgrades, new violations), then problems, transient items, and package changes grouped by ecosystem and site. Resolved items come last.
  - The body stays under Gmail's ~102 KB clipping limit. Long change lists are cut with "and N more", and the full folded digest is attached as JSON.
- **Schedule:** a digest is due at the first boundary after the last one was made. Boundaries are a fixed reference (a Monday, moved to `at` and `weekday`) plus multiples of `every`, in local wall-clock time, so a daily digest stays at `at` across DST and a `6h` or `2d` schedule is the same from run to run. It is sent if the digest is eventful (see Digest), or always when `send_unchanged` is set; otherwise its period still ends. A digest whose boundary passed while the app was not running is sent at the next start, covering the time since the last one. Without any digest state, the first digest covers everything already stored. A digest of a quiet period (no entries) takes the host from the latest stored entry, so a heartbeat still names it.
- **Period edges:** a period ends just after the latest entry it includes, not at the moment of sending. fetter writes in time order, so an event still in the pipe when a mail is built falls in the next period instead of between the two.
- **Immediate alerts:** when a `report` with status `alert` arrives and `alerts = "immediate"`, a short alert mail (the alert sections only, no attachment) covering the alert reports since the last alert mail is sent, rate-limited by `alert_min_interval`; one arriving sooner waits and joins the next. Those items are still included in the digest, marked "mailed": state.json keeps the spans the alert mails covered until a digest passes them.
- **Failure handling:** a failed send is retried with backoff (1 minute, doubling to an hour), and is shown in the Mail tab. The digest period does not advance until the send succeeds, so nothing is dropped. Every attempt is logged as a `mail` entry in `events/`, so a failed one is also a problem in the next digest.
- **Scheduler ticks:** `run` checks every 30 s, and at once when an alert report arrives. `digest --send` sends the pending digest now, whatever the schedule, and `check` verifies the credentials without sending (Postmark's server endpoint, or an SMTP login; `--offline` skips it).

## Storage

Everything fetter-scope keeps is in one directory, `~/.fetter-scope/` on every platform (Windows: `%USERPROFILE%\.fetter-scope\`), or `--home DIR` / `$FETTER_SCOPE_HOME`. It is created on first write with mode 0700, since events contain local paths. All files are plain:

```
config.toml                 configuration (or --config FILE)
.env                        credentials
bin/fetter                  fetter-scope's own fetter (see Contract with fetter)
events/YYYY-MM-DD.jsonl     every event line as received, plus fetter-scope's own entries, one per line; daily files (local date)
sites.json                  open vulnerabilities and known sites, folded from every report (`through`: the last report applied); rebuilt from `events/` when missing
state.json                  digest (period start, last run, result, backoff), alerts (covered spans, pending, backoff), mail history, the running fetter
mail/YYYY-MM-DDTHHMM.json   each digest sent (the folded dict), with .html and .txt beside it; alert mails as YYYY-MM-DDTHHMM-alert.*
```

- On start, the pending period's reports are rebuilt from `events/` since `state.json`'s last digest time. A restart therefore loses nothing.
- `sites.json` is written (temp file and rename) after each report by `run` and the TUI running fetter; on start it is topped up from stored reports after its `through`. `attach` reads it from the home of an `events/` directory it follows.
- Retention: `events/` older than 90 days is removed (`[store] retention_days`). Files under `mail/` are kept.
- Writes are append-and-flush for events, and temp-file-and-rename for `state.json`.
- fetter-scope's own entries are JSON objects shaped like events, with `"source": "fetter-scope"` (fetter's readers ignore them as unknown events): `launch` (pid, command), `fetter-exit` (code, expected, restart_in, terminated), `stderr` (line), `stdout` (a stdout line that is not an event), `control` (a command written), `protocol-error`, `supervisor-error` (restarts stopped), and `stale-stop` (a fetter left running by an earlier fetter-scope was stopped).
- `state.json` holds the running fetter's pid and binary while it runs, for the stale-process check.

## Repository layout

A separate repository, `fetter-scope`. It is a sibling of `fetter-rs`, not part of the Rust crate.

```
pyproject.toml          uv_build backend; textual, python-dotenv; dev: pytest, pytest-asyncio
fetter_scope/
  __main__.py           CLI: (default) tui, run [--headless], attach FILE, digest [--preview|--html|--json|--send], check, install-fetter
  home.py               the ~/.fetter-scope directory and its paths
  fetter_bin.py         resolve, version-check and install fetter-scope's own fetter binary
  config.py             config.toml + .env → frozen dataclasses
  events.py             event parsing (tolerant), the schema 1 event types as TypedDicts
  supervisor.py         launch, read, restart and stop fetter (asyncio subprocess); control channel (one outstanding request); attach (follow a file)
  store.py              events/, state.json, mail/
  digest.py             fold(entries, start, end) → digest; pure
  render.py             digest → HTML (inline styles) and text
  delivery.py           Postmark and SMTP; send_digest, send_alert → sent | failed | skipped
  scheduler.py          digest and alert timing; pure given "now"
  model.py              what the TUI shows, folded from entries (no Textual; tested directly)
  sites.py              open vulnerabilities per site over all history (Inventory; folding pure, saved as sites.json)
  tui.py                the Textual app
examples/
  systemd/              fetter-scope.service (a locked-down system service), its config.toml and credentials.env
  launchd/              io.fetter.fetter-scope.plist (a per-user LaunchAgent)
tests/
  fixtures/streams/     recorded monitor-diff streams (user, host and paths made generic, as fetter's tests/fixtures/monitor)
  fake_fetter.py        prints a fixture stream with delays, honors --version, can exit early, answers scan/report/stop on stdin
```

`fetter-scope check` validates the configuration, the fetter binary (its path, or how to install it) and version, and the mail credentials (a dry run with no send), then prints what would run.

## Testing

No test runs a real fetter scan, sends mail, or touches the network.
- **Events:** parsing every fixture, plus an unknown event, a newer schema, extra fields, and a non-JSON line.
- **Folding:**
  - upgrade then downgrade back (transient);
  - added then removed;
  - added then upgraded;
  - a vulnerability introduced then resolved;
  - a hook added then removed;
  - alert status kept after cancellation;
  - audit errors and missing scans as problems.
- **Scheduler:** `every`/`at`/`weekday` alignment, catch-up after downtime, alert rate limiting, and backoff. All are driven by an injected clock.
- **Supervisor:** `fake_fetter.py` for reading, restart with backoff, the three-exit stop, stopping on quit (`stop`, then terminate after the timeout), the version check, and attach-mode following of an appended file. Control channel: `s` is ignored while a request is outstanding, the next `request` scan acknowledges it, an unknown-command `error` is logged, a broken pipe is handled as an exit, and a stale pid in `state.json` is stopped.
- **Integration (optional, marked):** one test runs the real fetter on a temporary `Cargo.lock` project with a stubbed `--cache-directory` and drives `scan`, `report` and `stop`; skipped when fetter-scope's fetter binary is not installed or the network is unavailable.
- **Store:** restart rebuilds the pending period, plus retention.
- **Sites:** new minus resolved across reports, resolution by package version, idempotent re-application, a fixed baseline replacing the set, sites from changes and removal, per-site counts and order, `sites.json` saved per report and topped up from events after pruning.
- **Render:** a golden HTML and text for a fixture digest; the size limit with "and N more".
- **Delivery:** Postmark via a stubbed `urlopen`, and SMTP via a stubbed `smtplib.SMTP`. A failure does not advance the period.
- **TUI:** Textual pilot tests: tabs populate from a fixture stream, filters, the detail screen, copy, and the `m` and `s` keys with a fake supervisor and delivery.

## Milestones

1. [x] Skeleton: packaging, config, `check`, `install-fetter`, event parsing, fixture streams recorded from fetter.
2. [x] Supervisor and store: launch, attach, restart, control channel, `events/` log, headless `run` (log only).
3. [x] Digest folding and render (text and HTML), `digest --preview`.
4. [x] Delivery and scheduler: Postmark and SMTP, digests and immediate alerts, catch-up, `state.json`.
5. [x] TUI: header, Overview, Alerts (with detail), Changes, Live, Log.
6. [x] TUI: Vulnerabilities, Hooks, Mail tabs; keys; sorting and copy.
7. [x] launchd and systemd examples, README.
8. [x] TUI: Sites tab (per-site open vulnerabilities and CVSS summary), with the open-vulnerability state it needs.

## Out of scope for now

- Acting on findings: purging packages or accepting a baseline. These remain fetter commands, run by the user.
- Multiple systems. That is fetter.io's job (`monitor-scan`); fetter-scope is one system, one stream.
- An LLM-written summary, which assistant-bom has. This could be added later under the same rule: it only explains numbers it is given.
- Notifications other than email (Slack, webhooks, desktop). The delivery interface should allow adding them.

## Open questions

- **Transient changes in fetter:** fetter's reports already miss changes that appear and disappear between two of its reports. Should fetter-scope set `report_period = period` by default so that every scan can be reported (the default above), or should fetter accumulate them itself (fetter SPEC milestone 27 follow-up)?
- **Net classification after folding:** for the net kind of a folded package change (first `from` → last `to`), should fetter add a `compare` field, or a small `fetter compare-versions` command, rather than relying on the last step's kind?
- **Report acknowledgement:** after a `report` command, a `request` scan with no report following means nothing changed, but a reader can only tell by waiting. Should fetter always write a report for a `report` command (as `--report always` does), or emit a small `report-skipped` event?
- **Sites of hook-derived packages:** fetter 5.1.0 names no sites for a vulnerability in a package it derives from a pre-commit hook (e.g. `black` from `psf/black`); the site should be the `.pre-commit-config.yaml`. Recorded as an open known issue in fetter's SPEC; fetter-scope needs no change when it is fixed.
- **Interpreters run by a privileged scan:** fetter learns a Python's site-packages by running it (`python3 -S -c …`: `eco/python.rs` `get_site_package_dirs`, also `env_marker.rs`, `util.rs`). As a service with `--all-users` and `CAP_DAC_READ_SEARCH`, that runs any user's `bin/python3` beside a `pyvenv.cfg` with the capability (ambient, so inherited): shown in testing, where a planted script listed `/root`. fetter-scope's unit therefore forbids execution under homes and loses those venvs. Should fetter read a venv's `pyvenv.cfg` and layout instead of running it, or drop inherited capabilities (`PR_CAP_AMBIENT_CLEAR_ALL`) before running a discovered interpreter? Dropping them alone would not be enough, since without the capability fetter cannot run an interpreter inside another user's 0700 home at all; reading the layout covers both.
- **Control in attach mode:** should fetter add a file or socket control channel (`--control fifo:PATH`?) so a TUI attached to a service's stream can rescan? Until then, attach mode is read-only.
- **Settled:** a rescan trigger (fetter's `--control stdin`) and per-ecosystem counts (`scan.counts`) were added to fetter before 5.0.0.
- **Settled:** `VulnFinding` and `VulnResolved` carry `sites` (optional, from fetter 5.1.0; the stream stays at schema 1), so a `published` advisory against an unchanged package says where it is installed. The digest keeps the sites of the latest report naming each vulnerability, and mail shows them.
- **Settled:** the Sites tab's open vulnerabilities are kept by fetter-scope (`sites.json`), not sent by fetter: fetter 5.1.0 reports new and resolved findings only. If fetter later adds the current set to each report, it would cover a fixed baseline's own vulnerabilities and a fresh install without history.
- **Settled:** data, configuration and the fetter binary live in `~/.fetter-scope/`, not a repository directory, since the events contain local paths.
