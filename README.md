# fetter-scope

Real-time fetter display & notification via TUI & messaging.

fetter-scope runs `fetter monitor-diff`, shows what changes on a system, and emails digests and
alerts. See [SPEC.md](SPEC.md).

## Setup

```
uv tool install .                # or: pip install --user .
fetter-scope install-fetter      # installs fetter 5.1.0 to ~/.fetter-scope/bin (cargo, else PyPI)
fetter-scope check               # configuration, fetter binary, mail; prints what would run
```

fetter-scope keeps everything in `~/.fetter-scope/` (`--home DIR` or `$FETTER_SCOPE_HOME` to
change it): `config.toml`, `.env` (mail credentials), `bin/fetter`, and its event log. It runs its
own fetter binary, never the `fetter` on `PATH`.

## Upgrading from fetter 5.0.0

fetter 5.1.0 names the sites holding each vulnerable package, which the Sites tab uses. Findings
recorded under 5.0.0 have no sites, and a rolling baseline does not report them again. To have
them named, stop fetter-scope, run `fetter-scope install-fetter --force`, remove fetter's rolling
baseline (`monitor_diff_v1_*.json` in `~/.cache/io.fetter` on Linux, `~/Library/Caches/io.fetter`
on macOS), and start fetter-scope: the next report lists every existing vulnerability with its sites.

## Development

```
uv sync
uv run pytest
```
