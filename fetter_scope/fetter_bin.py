"""fetter-scope's own fetter binary: resolve it, check its version, install it.

fetter-scope runs `~/.fetter-scope/bin/fetter`, a version it pins (`FETTER_VERSION`), not
whatever `fetter` is on PATH (often an older PyPI install); `[fetter] binary` overrides it with an
explicit path. PATH is never searched. fetter is not a Python dependency.

`install` gets the binary from crates.io with `cargo install` when a Rust toolchain is present,
and otherwise from the PyPI wheel, fetched with urllib, checked against PyPI's sha256, and with
only the binary extracted (nothing is installed into the Python environment; `uv tool`
environments have no pip). Either way the binary is staged in a temp directory under the home,
checked with `--version`, then moved into place.
"""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fetter_scope import __version__
from fetter_scope.config import FetterConfig
from fetter_scope.home import Home

FETTER_VERSION = "5.1.0"
MIN_VERSION = (5, 1, 0)
PYPI_URL = "https://pypi.org/pypi/fetter/{version}/json"
RUSTUP_URL = "https://rustup.rs"
VERSION_TIMEOUT = 30
DOWNLOAD_TIMEOUT = 120

_VERSION_LINE = re.compile(r"^fetter\s+(\d+)\.(\d+)\.(\d+)(\S*)\s*$")


class InstallError(Exception):
    pass


def parse_version(s: str) -> tuple[int, int, int] | None:
    """`"fetter 5.0.0"` → (5, 0, 0); None if the first line is not fetter's version line."""
    first = s.strip().splitlines()[0] if s.strip() else ""
    m = _VERSION_LINE.match(first)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def _version_str(v: tuple[int, int, int]) -> str:
    return ".".join(map(str, v))


@dataclass(frozen=True)
class Resolved:
    path: Path
    configured: bool               # from [fetter] binary, not the home


def resolve(cfg: FetterConfig, home: Home) -> Resolved:
    """The binary to run: `[fetter] binary` if set, else the home's. It may not exist."""
    if cfg.binary:
        return Resolved(Path(cfg.binary).expanduser(), configured=True)
    return Resolved(home.fetter, configured=False)


@dataclass(frozen=True)
class Probe:
    path: Path
    version: tuple[int, int, int] | None = None
    error: str = ""                # empty when the binary is usable

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def version_str(self) -> str:
        return _version_str(self.version) if self.version else "unknown"


def install_hint(resolved: Resolved) -> str:
    if resolved.configured:
        return "check [fetter] binary in config.toml, or remove it to use fetter-scope's own"
    return "run `fetter-scope install-fetter`"


def probe(path: Path, run: Callable = subprocess.run) -> Probe:
    """Run `<path> --version`; refuse a missing binary, an unrecognized one, or one below `MIN_VERSION`."""
    if not path.exists():
        return Probe(path, error=f"no fetter binary at {path}")
    try:
        proc = run([str(path), "--version"], capture_output=True, text=True,
                   timeout=VERSION_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as e:
        return Probe(path, error=f"cannot run {path}: {e}")
    version = parse_version(proc.stdout or "")
    if proc.returncode != 0 or version is None:
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        return Probe(path, error=f"{path} --version did not report a fetter version"
                                 + (f": {out[0]!r}" if out else ""))
    if version < MIN_VERSION:
        return Probe(path, version, error=f"{path} is fetter {_version_str(version)}; "
                                          f"fetter-scope requires {_version_str(MIN_VERSION)} or later")
    return Probe(path, version)


def monitor_diff_command(binary: Path, cfg: FetterConfig) -> list[str]:
    """The long-running `monitor-diff` command fetter-scope launches (see SPEC: Launch)."""
    cmd = [str(binary), *cfg.args, "monitor-diff",
           "--period", str(cfg.period), "--report-period", str(cfg.report_period)]
    if cfg.report != "change":
        cmd += ["--report", cfg.report]
    if cfg.baseline:
        cmd += ["--baseline", str(Path(cfg.baseline).expanduser())]
    if cfg.bound:
        cmd += ["--bound", str(Path(cfg.bound).expanduser())]
        for opt in cfg.bound_options:
            cmd += ["--bound-options", opt]
        cmd += [flag for flag, on in (("--subset", cfg.subset), ("--superset", cfg.superset),
                                      ("--strict", cfg.strict)) if on]
    if cfg.cvss:
        cmd.append(f"--cvss={cfg.cvss:g}")
    cmd += ["--control", "stdin", "json"]
    return cmd


#-------------------------------------------------------------------------------
# install

def _cargo_install(staging: Path, version: str, run: Callable, cargo: str) -> Path:
    """`cargo install` into `staging`; its output goes to the terminal (a build takes minutes)."""
    cmd = [cargo, "install", "fetter", "--version", f"={version}", "--locked",
           "--root", str(staging)]
    print("$ " + " ".join(cmd), flush=True)
    # staging/bin on PATH only quiets cargo's "add it to your PATH" warning about the temp dir
    path = os.pathsep.join(p for p in (str(staging / "bin"), os.environ.get("PATH", "")) if p)
    proc = run(cmd, env={**os.environ, "PATH": path})
    if proc.returncode != 0:
        raise InstallError(f"cargo install failed (exit {proc.returncode})")
    return staging / "bin" / Home(staging).fetter.name


def _platform_matches(tag: str) -> bool:
    """Whether a wheel's platform tag (e.g. `manylinux_2_17_x86_64.manylinux2014_x86_64`) runs here."""
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    tags = tag.split(".")
    if sys.platform == "win32":
        want = {"x86_64": "win_amd64", "aarch64": "win_arm64", "x86": "win32"}.get(arch)
        return want in tags
    if sys.platform == "darwin":
        mac = "arm64" if arch == "aarch64" else arch
        return any(t.startswith("macosx_") and (t.endswith("_" + mac) or t.endswith("_universal2"))
                   for t in tags)
    if sys.platform.startswith("linux"):
        musl = platform.libc_ver()[0] != "glibc"
        prefix = ("musllinux_",) if musl else ("manylinux_", "manylinux1", "manylinux2")
        return any(t.startswith(prefix) and t.endswith("_" + arch) for t in tags)
    return False


def _select_wheel(files: list[dict]) -> dict | None:
    """The first binary wheel whose platform tag matches this system."""
    for f in files:
        name = f.get("filename", "")
        if f.get("packagetype") != "bdist_wheel" or not name.endswith(".whl"):
            continue
        parts = name[:-4].split("-")
        if len(parts) >= 5 and _platform_matches(parts[-1]):
            return f
    return None


def _fetch(url: str, urlopen_: Callable) -> bytes:
    req = Request(url, headers={"User-Agent": f"fetter-scope/{__version__}"})
    with urlopen_(req, timeout=DOWNLOAD_TIMEOUT) as resp:
        return resp.read()


def _pypi_install(staging: Path, version: str, urlopen_: Callable) -> Path:
    no_pypi = (f"fetter {version} is not on PyPI (yet); install a Rust toolchain "
               f"({RUSTUP_URL}) and retry, which builds it with cargo")
    try:
        meta = json.loads(_fetch(PYPI_URL.format(version=version), urlopen_))
    except HTTPError as e:
        if e.code == 404:
            raise InstallError(no_pypi) from None
        raise InstallError(f"PyPI: HTTP {e.code}") from None
    except (URLError, OSError, ValueError) as e:
        raise InstallError(f"PyPI: {getattr(e, 'reason', e)}") from None

    wheel = _select_wheel(meta.get("urls", []))
    if wheel is None:
        raise InstallError(f"no fetter {version} wheel on PyPI for {sys.platform} "
                           f"{platform.machine()}; install a Rust toolchain ({RUSTUP_URL}) and retry")
    print(f"downloading {wheel['filename']}", flush=True)
    try:
        data = _fetch(wheel["url"], urlopen_)
    except (URLError, OSError) as e:
        raise InstallError(f"download failed: {getattr(e, 'reason', e)}") from None
    expect = wheel.get("digests", {}).get("sha256")
    if not expect or hashlib.sha256(data).hexdigest() != expect:
        raise InstallError(f"{wheel['filename']}: sha256 does not match PyPI's")

    target = staging / "bin" / Home(staging).fetter.name
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [n for n in zf.namelist()
                   if re.fullmatch(r"fetter-[^/]+\.data/scripts/" + re.escape(target.name), n)]
        if not members:
            raise InstallError(f"{wheel['filename']} holds no fetter binary")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(members[0]))
    target.chmod(0o755)
    return target


def install(home: Home, method: str = "auto", force: bool = False, *,
            version: str = FETTER_VERSION,
            run: Callable = subprocess.run,
            which: Callable = shutil.which,
            urlopen_: Callable = urlopen) -> str:
    """Install fetter `version` at `home.fetter`; returns a one-line result. Raises InstallError.

    `method`: "auto" (cargo if on PATH, else PyPI), "cargo", or "pypi".
    """
    if method not in ("auto", "cargo", "pypi"):
        raise InstallError(f"unknown method {method!r}")
    want = parse_version(f"fetter {version}")
    if not force and home.fetter.exists():
        current = probe(home.fetter, run)
        if current.version == want:
            return f"fetter {version} is already installed at {home.fetter}"

    cargo = which("cargo") if method in ("auto", "cargo") else None
    if method == "cargo" and cargo is None:
        raise InstallError(f"cargo is not on PATH; install a Rust toolchain ({RUSTUP_URL}) "
                           "or use --method pypi")

    try:
        home.ensure()
        staging = Path(tempfile.mkdtemp(prefix=".install-", dir=home.root))
    except OSError as e:
        raise InstallError(f"cannot write to {home.root}: {e.strerror or e}") from None
    try:
        if cargo:
            built = _cargo_install(staging, version, run, cargo)
            source = "crates.io (cargo)"
        else:
            built = _pypi_install(staging, version, urlopen_)
            source = "PyPI"
        if not built.exists():
            raise InstallError(f"the install produced no binary at {built}")
        checked = probe(built, run)
        if not checked.ok:
            raise InstallError(checked.error)
        if checked.version != want:
            raise InstallError(f"installed binary reports {checked.version_str}, expected {version}")
        try:
            home.bin_dir.mkdir(parents=True, exist_ok=True)
            os.replace(built, home.fetter)
        except OSError as e:
            raise InstallError(f"cannot install to {home.fetter}: {e.strerror or e}") from None
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return f"installed fetter {version} from {source} at {home.fetter}"
