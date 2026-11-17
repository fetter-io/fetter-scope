# fetter-scope

Real-time fetter display & notification via TUI & messaging.

fetter-scope runs `fetter monitor-diff`, shows what changes on a system (packages, sites and
origins; new vulnerabilities, including advisories newly published against packages that did
not change; new hooks, downgrades and allow-list violations), and emails digests and alerts.
fetter does the scanning and evaluation; fetter-scope launches it, displays its event stream,
accumulates it, and delivers it. See [SPEC.md](SPEC.md) for the design.

## Setup

Requires Python 3.14 and fetter 5.1.0 or later.

```
uv tool install .                # or: pip install --user .
fetter-scope install-fetter      # installs fetter 5.1.0 to ~/.fetter-scope/bin (cargo, else PyPI)
fetter-scope check               # configuration, fetter binary, mail; prints what would run
fetter-scope                     # the terminal app
```

fetter 5.1.0 is not yet on PyPI, so without a Rust toolchain (`cargo` on `PATH`)
`install-fetter` fails for now.

fetter-scope keeps everything in `~/.fetter-scope/` (`--home DIR` or `$FETTER_SCOPE_HOME` to
change it), created with mode 0700 since events contain user names and paths:

```
config.toml        configuration (or --config FILE); every key is optional
.env               mail credentials
bin/fetter         fetter-scope's own fetter; the `fetter` on PATH is never used
events/            every event, one JSON Lines file per day (kept 90 days)
sites.json         open vulnerabilities per site, over all history
state.json         digest and alert state, mail history, the running fetter
mail/              each digest and alert sent (JSON, HTML, text)
```

## Commands

| Command | |
|---|---|
| `fetter-scope` (or `tui`, `run`) | the terminal app, running fetter; it first replays the pending digest period from `events/` |
| `fetter-scope run --headless` | the same without the TUI, one line per event: for a service |
| `fetter-scope attach FILE` | follow a stream read-only: a `monitor-diff json -o FILE` written by fetter, or a fetter-scope `events/` directory (e.g. a service's). `--print` prints lines instead of the TUI |
| `fetter-scope digest` | print the pending digest; `--html` opens it in a browser, `--json` prints the folded digest, `--send` mails it now |
| `fetter-scope check [--offline]` | validate the configuration, the fetter binary and the mail credentials (without sending) |
| `fetter-scope install-fetter [--method auto\|cargo\|pypi] [--force]` | install the pinned fetter |

## The terminal app

**Tabs** (`1`–`9`):

1. **Overview**: per-ecosystem counts of origins, sites and packages from the latest scan (an
   ecosystem that drops to zero is highlighted), a packages sparkline, the latest report and
   the pending digest's counts.
2. **Alerts**: one row per new vulnerability, hook, downgrade or violation, and whether it has
   been mailed.
3. **Changes**: every package change, folded since the last digest or every report (`t`).
4. **Live**: the changes each scan finds, as they arrive, ahead of fetter's next report.
5. **Vulnerabilities**: new, resolved and transient vulnerabilities in the digest period, by CVSS.
6. **Sites**: one row per site with its open vulnerabilities (CVSS max and median, critical and
   high counts), worst first, over all history.
7. **Hooks**: added, removed and transient hooks, shown verbatim (never run).
8. **Mail**: transport, recipients, schedule, history, and a preview of the pending digest.
9. **Log**: raw events and fetter's stderr; errors highlighted.

**Keys:**

| Key | |
|---|---|
| `s` / `r` | rescan now / report now (on fetter's control channel; not in attach mode) |
| `m` | send the digest now (after a report, so it is current) |
| `p` | preview the digest's HTML in a browser |
| `c` / `u` | copy the selected row's name or ID / its URL |
| `/`, Escape | filter the current tab (`key:value` words match a column, e.g. `eco:npm kind:down`), clear |
| `t` | Changes: since the last digest, or every report |
| `e` | the ecosystem selector: Left/Right, space toggles, `o` only this one, Down back to the table |
| Enter, Escape | open and close a row's detail |
| `l` | reload `config.toml` (mail settings apply at once; fetter settings need a restart) |
| `q` | quit; fetter is stopped (`q` again terminates it now) |

Above the Alerts, Changes, Live, Vulnerabilities and Hooks tables, a row of ecosystem
checkboxes (with each one's row count) chooses which ecosystems those tabs show; one selection
applies to all five. Column headers sort: ascending, descending, then the original order.

## Configuration

`~/.fetter-scope/config.toml`, read and never written. The full set of keys and their defaults
is in [SPEC.md](SPEC.md#configuration); the common ones:

```toml
[fetter]
args = ["-E", "python,npm"]   # fetter's global args: ecosystems, --root DIR, ...
period = 300                  # seconds between scans
report_period = 300           # seconds between reports (each advances fetter's rolling baseline)
baseline = ""                 # a fixed baseline from `fetter monitor-diff save`; "" is rolling
cvss = 0                      # report only vulnerabilities at or above this score

[mail]
enabled = true
transport = "postmark"        # or "smtp"
every = "1d"                  # digest frequency: "6h", "1d", "7d", ...
at = "07:00"                  # local time, for whole days
weekday = ""                  # e.g. "mon", with every = "7d"
send_unchanged = false        # also send a digest when nothing happened
alerts = "immediate"          # mail alert reports as they arrive, or "digest" to wait
alert_min_interval = "15m"
```

**Mail credentials** are never in `config.toml`. They come from the environment, over a
systemd credential (see below), over the `.env` beside `config.toml`:

```
REPORT_EMAIL_FROM=fetter@example.org
REPORT_EMAIL_TO=you@example.org            # comma-separated
POSTMARK_SERVER_TOKEN=...                  # transport = "postmark"
SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... SMTP_PASSWORD=... SMTP_TLS=starttls   # transport = "smtp"
```

A digest is sent at each boundary of `every` when something happened (or always, with
`send_unchanged`); one missed while nothing was running is sent at the next start. A failed send
is retried with backoff and the period does not advance, so nothing is dropped. `fetter-scope
check` verifies the credentials without sending.

## Running as a service

`run --headless` runs fetter, the event log and the mail scheduler without a terminal. Its
SIGTERM handling writes `stop` to fetter and waits up to 30 s for a scan in progress, so a
service manager should allow about 45 s before killing it. View a running service with
`fetter-scope attach <home>/events` (read-only: no rescan or report keys).

### Linux: systemd

[`examples/systemd/fetter-scope.service`](examples/systemd/fetter-scope.service) runs it as a
locked-down system service that scans every user's home:

- a `DynamicUser` with no login or home, writing only `/var/lib/fetter-scope`;
- one capability, `CAP_DAC_READ_SEARCH`, to read other users' packages (drop it and give fetter
  `--root DIR` to watch one tree), with `/etc/shadow`, SSH keys, sudoers and the credentials file
  made inaccessible;
- nothing executable outside `/opt/fetter-scope`, `/usr/bin`, `/usr/local/bin` and the shared
  libraries: not under homes, `/tmp` or the state directory (see below);
- outbound network only (no listening sockets, no link-local or cloud metadata addresses);
- the `@system-service` system calls less privileged and resource-control ones, no namespaces,
  no W+X memory, private `/tmp`, devices and IPC, and the kernel, clock and cgroups protected;
- mail secrets passed as a systemd credential, never in the environment, so fetter does not
  inherit them;
- low CPU and I/O priority, and memory and task limits.

`systemd-analyze security fetter-scope.service` rates it 1.6 (OK); the remaining
exposure is what it needs: the network, the read capability, read access to homes, and no
private user namespace (one would stop the capability from reading other users' files).

**Interpreters in homes are not run.** fetter learns a Python's site-packages by running it
(`python3 -S -c ...`), and the service's capability is passed on to what it runs. If the
service could execute files under `/home`, any local user could put a `bin/python3` beside a
`pyvenv.cfg` and have it run with read access to every file on the system. So a virtual
environment whose interpreter links to `/usr/bin/python3` is scanned, but one whose interpreter
lives in a home is not: uv-managed Pythons (`~/.local/share/uv/python`), pyenv, conda, and
`venv --copies`. To scan those, allow execution in the homes (or just the interpreter
directories) of users you trust with that read access, with a drop-in:

```
# /etc/systemd/system/fetter-scope.service.d/exec-homes.conf
[Service]
ExecPaths=/home/alice /home/bob/.local/share/uv/python
```

Name directories below `/home`: `ExecPaths=/home` itself has no effect, since the `/home` mount
that `ProtectHome=` (implied by `DynamicUser=`) makes takes its place.

Tested on Debian trixie (systemd 257): the scan, credentials, a graceful stop, the read-only and
no-exec paths, the hidden files and the address restrictions. `SocketBindDeny=` needs kernel
BPF support (it was not applied in a Docker Desktop VM, where systemd skips it silently).

Install into `/opt/fetter-scope`, with a uv-managed Python 3.14 inside it so the install is
self-contained and root-owned:

```
sudo env UV_PYTHON_INSTALL_DIR=/opt/fetter-scope/python \
    "$(command -v uv)" venv --allow-existing --managed-python --python 3.14 /opt/fetter-scope
sudo "$(command -v uv)" pip install --python /opt/fetter-scope/bin/python --compile-bytecode .
sudo /opt/fetter-scope/bin/fetter-scope --home /opt/fetter-scope install-fetter   # → /opt/fetter-scope/bin/fetter
```

Without a root Rust toolchain, build fetter as yourself (`cargo install fetter --version =5.1.0
--locked`) and copy it: `sudo install -m 0755 ~/.cargo/bin/fetter /opt/fetter-scope/bin/fetter`.

Then the configuration, credentials and unit:

```
sudo install -d -m 0755 /etc/fetter-scope
sudo install -m 0644 examples/systemd/config.toml /etc/fetter-scope/config.toml
sudo install -m 0600 examples/systemd/credentials.env /etc/fetter-scope/credentials.env   # edit; must exist, may be empty
sudo install -m 0644 examples/systemd/fetter-scope.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fetter-scope
journalctl -u fetter-scope -f
```

`config.toml` points fetter at `/opt/fetter-scope/bin/fetter`, adds `--all-users`, and keeps
fetter's cache (its rolling baseline) in `/var/lib/fetter-scope/fetter`. To check the mail
credentials as the service sees them:

```
sudo systemd-run --pipe --wait -p DynamicUser=yes -p StateDirectory=fetter-scope \
    -p LoadCredential=dotenv:/etc/fetter-scope/credentials.env \
    /opt/fetter-scope/bin/fetter-scope --home /var/lib/fetter-scope \
    --config /etc/fetter-scope/config.toml check
```

To watch it: `sudo /opt/fetter-scope/bin/fetter-scope attach /var/lib/fetter-scope/events`.

### macOS: launchd

[`examples/launchd/io.fetter.fetter-scope.plist`](examples/launchd/io.fetter.fetter-scope.plist)
is a per-user LaunchAgent: it runs as you, scans your home, and uses `~/.fetter-scope` as
usual. launchd does not expand `~`, so replace `/Users/YOU` in it, then:

```
cp examples/launchd/io.fetter.fetter-scope.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.fetter.fetter-scope.plist
fetter-scope attach ~/.fetter-scope/events
launchctl bootout gui/$(id -u)/io.fetter.fetter-scope      # to stop it
```

It restarts after a crash (at most every 10 minutes), runs at background priority with umask
0077, and gives fetter-scope 45 s to stop. macOS privacy controls can keep a background process
out of `~/Documents`, `~/Desktop` and `~/Downloads`; give `~/.fetter-scope/bin/fetter` Full Disk
Access (System Settings, Privacy & Security) for packages there to be seen.

## Upgrading from fetter 5.0.0

fetter 5.1.0 names the sites holding each vulnerable package, which the Sites tab uses. Findings
recorded under 5.0.0 have no sites, and a rolling baseline does not report them again. To have
them named, stop fetter-scope, run `fetter-scope install-fetter --force`, remove fetter's rolling
baseline (`monitor_diff_v1_*.json` in `~/.cache/io.fetter` on Linux, `~/Library/Caches/io.fetter`
on macOS, or the service's `/var/lib/fetter-scope/fetter`), and start fetter-scope: the next
report lists every existing vulnerability with its sites.

## Development

```
uv sync
uv run pytest      # no test runs a real fetter, sends mail or uses the network
```
