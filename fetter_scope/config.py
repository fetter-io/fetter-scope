"""config.toml and .env → frozen dataclasses.

config.toml is read with tomllib and never written. Every key is optional; defaults match
SPEC.md. Problems (a TOML syntax error, an unknown key, a value of the wrong type or form) do
not raise: each is collected in `Config.errors`, the default is used in its place, and `check`
prints them all at once.

Credentials come from the process environment, over a systemd credential named `dotenv`
(`$CREDENTIALS_DIRECTORY/dotenv`, from `LoadCredential=`; `.env` format), over the `.env` beside
config.toml. The process environment is not modified, so none of them reaches fetter's.
"""
import os
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from dotenv import dotenv_values

from fetter_scope.home import Home

TRANSPORTS = ("postmark", "smtp")
ALERT_MODES = ("immediate", "digest")
REPORT_WHEN = ("change", "always")
SMTP_TLS = ("starttls", "ssl")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_TIME_OF_DAY = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def parse_duration(s: str) -> int:
    """`"30s"`, `"15m"`, `"6h"`, `"1d"` → seconds (above 0). Raises ValueError."""
    m = _DURATION.match(s) if isinstance(s, str) else None
    if not m or int(m.group(1)) == 0:
        raise ValueError(f"expected a duration such as \"15m\", \"6h\" or \"1d\", got {s!r}")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def parse_time_of_day(s: str) -> tuple[int, int]:
    """`"07:00"` → (7, 0). Raises ValueError."""
    m = _TIME_OF_DAY.match(s) if isinstance(s, str) else None
    if not m:
        raise ValueError(f"expected a time such as \"07:00\", got {s!r}")
    return int(m.group(1)), int(m.group(2))


@dataclass(frozen=True)
class FetterConfig:
    binary: str = ""             # "" is fetter-scope's own, ~/.fetter-scope/bin/fetter
    args: tuple[str, ...] = ()   # global args, before `monitor-diff`
    period: int = 300
    report_period: int = 300
    report: str = "change"       # fetter's --report: "change" or "always"
    baseline: str = ""           # a fixed baseline file; "" is rolling
    bound: str = ""
    bound_options: tuple[str, ...] = ()
    subset: bool = False
    superset: bool = False
    strict: bool = False
    cvss: float = 0              # 0 is no filter


@dataclass(frozen=True)
class MailConfig:
    enabled: bool = False
    transport: str = "postmark"
    every: int = 86400                 # seconds, from "1d"
    at: tuple[int, int] = (7, 0)       # local (hour, minute)
    weekday: str = ""                  # "" or one of WEEKDAYS
    send_unchanged: bool = False
    alerts: str = "immediate"
    alert_min_interval: int = 900      # seconds, from "15m"
    subject_prefix: str = "fetter"


@dataclass(frozen=True)
class TuiConfig:
    theme: str = ""
    feed_limit: int = 2000


@dataclass(frozen=True)
class StoreConfig:
    retention_days: int = 90           # events/ files older than this are removed; 0 keeps all


@dataclass(frozen=True)
class Credentials:
    email_from: str = ""
    email_to: tuple[str, ...] = ()
    postmark_token: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_tls: str = "starttls"

    @classmethod
    def from_env(cls, env: Mapping[str, str], errors: list[str]) -> "Credentials":
        port = 587
        if raw := env.get("SMTP_PORT", "").strip():
            try:
                port = int(raw)
            except ValueError:
                errors.append(f"SMTP_PORT: expected an integer, got {raw!r}")
        tls = env.get("SMTP_TLS", "").strip().lower() or "starttls"
        if tls not in SMTP_TLS:
            errors.append(f"SMTP_TLS: expected one of {', '.join(SMTP_TLS)}, got {tls!r}")
            tls = "starttls"
        return cls(
            email_from=env.get("REPORT_EMAIL_FROM", "").strip(),
            email_to=tuple(a.strip() for a in env.get("REPORT_EMAIL_TO", "").split(",") if a.strip()),
            postmark_token=env.get("POSTMARK_SERVER_TOKEN", "").strip(),
            smtp_host=env.get("SMTP_HOST", "").strip(),
            smtp_port=port,
            smtp_user=env.get("SMTP_USER", "").strip(),
            smtp_password=env.get("SMTP_PASSWORD", ""),
            smtp_tls=tls,
        )

    def missing(self, transport: str) -> list[str]:
        """Names of the environment variables `transport` needs that are not set."""
        need = {"REPORT_EMAIL_FROM": self.email_from, "REPORT_EMAIL_TO": self.email_to}
        if transport == "postmark":
            need["POSTMARK_SERVER_TOKEN"] = self.postmark_token
        elif transport == "smtp":
            need["SMTP_HOST"] = self.smtp_host
        return [k for k, v in need.items() if not v]


@dataclass(frozen=True)
class Config:
    home: Home
    path: Path                     # the config.toml read, or that would be read
    found: bool                    # whether `path` existed
    fetter: FetterConfig = field(default_factory=FetterConfig)
    mail: MailConfig = field(default_factory=MailConfig)
    tui: TuiConfig = field(default_factory=TuiConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    credentials: Credentials = field(default_factory=Credentials)
    errors: tuple[str, ...] = ()

    @property
    def mail_missing(self) -> list[str]:
        return self.credentials.missing(self.mail.transport)


#-------------------------------------------------------------------------------

class _Section:
    """Typed reads from one TOML table, recording errors and unknown keys."""

    def __init__(self, name: str, table: object, errors: list[str]):
        self.name = name
        self.errors = errors
        if not isinstance(table, dict):
            errors.append(f"[{name}]: expected a table")
            table = {}
        self.table = table
        self.used: set[str] = set()

    def _err(self, key: str, msg: str) -> None:
        self.errors.append(f"[{self.name}] {key}: {msg}")

    def get(self, key: str, default, kind):
        """The value at `key` if it is an instance of `kind` (bool is never an int or float)."""
        self.used.add(key)
        if key not in self.table:
            return default
        v = self.table[key]
        kinds = kind if isinstance(kind, tuple) else (kind,)
        if isinstance(v, bool) and bool not in kinds:
            ok = False
        else:
            ok = isinstance(v, kinds)
        if not ok:
            names = " or ".join(k.__name__ for k in kinds)
            self._err(key, f"expected {names}, got {v!r}")
            return default
        return v

    def choice(self, key: str, default: str, choices: tuple[str, ...]) -> str:
        v = self.get(key, default, str)
        if v not in choices:
            self._err(key, f"expected one of {', '.join(choices)}, got {v!r}")
            return default
        return v

    def strings(self, key: str) -> tuple[str, ...]:
        v = self.get(key, [], list)
        if not all(isinstance(s, str) for s in v):
            self._err(key, f"expected a list of strings, got {v!r}")
            return ()
        return tuple(v)

    def non_negative(self, key: str, default, kind=int):
        v = self.get(key, default, kind)
        if v < 0:
            self._err(key, f"expected 0 or more, got {v!r}")
            return default
        return v

    def positive(self, key: str, default: int) -> int:
        v = self.get(key, default, int)
        if v <= 0:
            self._err(key, f"expected above 0, got {v!r}")
            return default
        return v

    def parsed(self, key: str, default, parse):
        """A string value converted by `parse`; the default is returned unparsed."""
        if key not in self.table:
            self.used.add(key)
            return default
        raw = self.get(key, None, str)
        if raw is None:
            return default
        try:
            return parse(raw)
        except ValueError as e:
            self._err(key, str(e))
            return default

    def finish(self) -> None:
        for key in sorted(set(self.table) - self.used):
            self._err(key, "unknown key")


def _fetter(s: _Section) -> FetterConfig:
    period = s.positive("period", 300)
    cfg = FetterConfig(
        binary=s.get("binary", "", str),
        args=s.strings("args"),
        period=period,
        report_period=s.positive("report_period", period),
        report=s.choice("report", "change", REPORT_WHEN),
        baseline=s.get("baseline", "", str),
        bound=s.get("bound", "", str),
        bound_options=s.strings("bound_options"),
        subset=s.get("subset", False, bool),
        superset=s.get("superset", False, bool),
        strict=s.get("strict", False, bool),
        cvss=s.non_negative("cvss", 0, (int, float)),
    )
    if cfg.cvss > 10:
        s._err("cvss", f"expected 0 to 10, got {cfg.cvss!r}")
        cfg = replace(cfg, cvss=0)
    return cfg


def _mail(s: _Section) -> MailConfig:
    every = s.parsed("every", 86400, parse_duration)
    weekday = s.get("weekday", "", str).strip().lower()
    if weekday and weekday not in WEEKDAYS:
        s._err("weekday", f"expected one of {', '.join(WEEKDAYS)}, got {weekday!r}")
        weekday = ""
    if weekday and every != 7 * 86400:
        s._err("weekday", "only applies when every is \"7d\"")
    return MailConfig(
        enabled=s.get("enabled", False, bool),
        transport=s.choice("transport", "postmark", TRANSPORTS),
        every=every,
        at=s.parsed("at", (7, 0), parse_time_of_day),
        weekday=weekday,
        send_unchanged=s.get("send_unchanged", False, bool),
        alerts=s.choice("alerts", "immediate", ALERT_MODES),
        alert_min_interval=s.parsed("alert_min_interval", 900, parse_duration),
        subject_prefix=s.get("subject_prefix", "fetter", str),
    )


def _tui(s: _Section) -> TuiConfig:
    return TuiConfig(theme=s.get("theme", "", str), feed_limit=s.positive("feed_limit", 2000))


def _store(s: _Section) -> StoreConfig:
    return StoreConfig(retention_days=s.non_negative("retention_days", 90))


CREDENTIAL = "dotenv"                    # the systemd credential holding .env-format secrets


def env_files(config_path: Path, environ: Mapping[str, str]) -> list[Path]:
    """The credential files read, lowest precedence first: the `.env` beside `config_path`, then
    the systemd credential `$CREDENTIALS_DIRECTORY/dotenv` (a service's `LoadCredential=`)."""
    found = [config_path.parent / ".env"]
    if cred_dir := environ.get("CREDENTIALS_DIRECTORY"):
        found.append(Path(cred_dir) / CREDENTIAL)
    return [p for p in found if p.is_file()]


_SECTIONS = {"fetter": _fetter, "mail": _mail, "tui": _tui, "store": _store}


def load(home: Home, config_path: str | os.PathLike | None = None,
         environ: Mapping[str, str] | None = None) -> Config:
    """Read `config_path` (default `home.config`) and the `.env` beside it.

    `environ` defaults to `os.environ`; its values win over the files of `env_files`.
    """
    path = Path(config_path).expanduser() if config_path is not None else home.config
    errors: list[str] = []
    data: dict = {}
    found = path.is_file()
    if found:
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            errors.append(f"{path}: {e}")
        except OSError as e:
            errors.append(f"{path}: {e.strerror or e}")
    elif config_path is not None:
        errors.append(f"{path}: not found")

    parts = {}
    for name, build in _SECTIONS.items():
        s = _Section(name, data.get(name, {}), errors)
        parts[name] = build(s)
        s.finish()
    for name in sorted(set(data) - set(_SECTIONS)):
        errors.append(f"[{name}]: unknown table")

    environ = os.environ if environ is None else environ
    env: dict[str, str] = {}
    for env_path in env_files(path, environ):
        env.update({k: v for k, v in dotenv_values(env_path).items() if v is not None})
    env.update(environ)
    credentials = Credentials.from_env(env, errors)

    return Config(home=home, path=path, found=found, credentials=credentials,
                  errors=tuple(errors), **parts)
