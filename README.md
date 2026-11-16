# fetter-scope

Real-time fetter display & notification via TUI & messaging.

fetter-scope runs `fetter monitor-diff`, shows what changes on a system, and emails digests and
alerts. See [SPEC.md](SPEC.md).

## Setup

```
uv tool install .                # or: pip install --user .
fetter-scope install-fetter      # installs fetter 5.0.0 to ~/.fetter-scope/bin (cargo, else PyPI)
fetter-scope check               # configuration, fetter binary, mail; prints what would run
```

fetter-scope keeps everything in `~/.fetter-scope/` (`--home DIR` or `$FETTER_SCOPE_HOME` to
change it): `config.toml`, `.env` (mail credentials), `bin/fetter`, and its event log. It runs its
own fetter binary, never the `fetter` on `PATH`.

## Development

```
uv sync
uv run pytest
```
