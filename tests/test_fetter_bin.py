import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from urllib.error import HTTPError

import pytest

from fetter_scope import fetter_bin
from fetter_scope.config import FetterConfig
from fetter_scope.fetter_bin import InstallError

from tests.conftest import fake_fetter

FAKE_SCRIPT = "#!/bin/sh\necho 'fetter 5.1.0'\n"


# resolve / probe -------------------------------------------------------------

def test_resolve_home_ignores_path(home, tmp_path, monkeypatch):
    fake_fetter(tmp_path / "pathbin" / "fetter", "5.1.0")
    monkeypatch.setenv("PATH", str(tmp_path / "pathbin"))
    r = fetter_bin.resolve(FetterConfig(), home)
    assert r == fetter_bin.Resolved(home.fetter, configured=False)
    assert not fetter_bin.probe(r.path).ok


def test_resolve_configured(home):
    r = fetter_bin.resolve(FetterConfig(binary="~/x/fetter"), home)
    assert r.configured and r.path == Path("~/x/fetter").expanduser()


@pytest.mark.parametrize("text,expect", [
    ("fetter 5.0.0\n", (5, 0, 0)),
    ("fetter 12.3.45-rc1", (12, 3, 45)),
    ("fetter-scope 5.0.0", None),
    ("", None),
    ("oops\nfetter 5.0.0", None),
])
def test_parse_version(text, expect):
    assert fetter_bin.parse_version(text) == expect


def test_probe_ok(tmp_path):
    p = fetter_bin.probe(fake_fetter(tmp_path / "fetter", "5.1.2"))
    assert p.ok and p.version == (5, 1, 2) and p.version_str == "5.1.2"


def test_probe_old(tmp_path):
    p = fetter_bin.probe(fake_fetter(tmp_path / "fetter", "3.1.0"))
    assert not p.ok and p.version == (3, 1, 0)
    assert "fetter 3.1.0" in p.error and "requires 5.1.0" in p.error


def test_probe_missing(tmp_path):
    p = fetter_bin.probe(tmp_path / "nope")
    assert not p.ok and "no fetter binary" in p.error


def test_probe_not_fetter(tmp_path):
    path = tmp_path / "fetter"
    path.write_text("#!/bin/sh\necho hello\n")
    path.chmod(0o755)
    p = fetter_bin.probe(path)
    assert not p.ok and "did not report" in p.error


def test_install_hint():
    assert "install-fetter" in fetter_bin.install_hint(fetter_bin.Resolved(Path("x"), False))
    assert "[fetter] binary" in fetter_bin.install_hint(fetter_bin.Resolved(Path("x"), True))


# command ----------------------------------------------------------------------

def test_command_default():
    assert fetter_bin.monitor_diff_command(Path("/b/fetter"), FetterConfig()) == [
        "/b/fetter", "monitor-diff", "--period", "300", "--report-period", "300",
        "--control", "stdin", "json"]


def test_command_full():
    cfg = FetterConfig(args=("-E", "python"), period=60, report_period=120, report="always",
                       baseline="/b.json", bound="/r.txt", bound_options=("dev", "test"),
                       superset=True, strict=True, cvss=7)
    assert fetter_bin.monitor_diff_command(Path("f"), cfg) == [
        "f", "-E", "python", "monitor-diff", "--period", "60", "--report-period", "120",
        "--report", "always", "--baseline", "/b.json", "--bound", "/r.txt",
        "--bound-options", "dev", "--bound-options", "test", "--superset", "--strict",
        "--cvss=7", "--control", "stdin", "json"]


# install ----------------------------------------------------------------------

class Runner:
    """Stands in for subprocess.run: fakes `cargo install`, runs `--version` for real."""

    def __init__(self, version="5.1.0", fail=False):
        self.version, self.fail, self.calls = version, fail, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if cmd[1:2] == ["install"]:
            if self.fail:
                return subprocess.CompletedProcess(cmd, 101)
            root = Path(cmd[cmd.index("--root") + 1])
            fake_fetter(root / "bin" / "fetter", self.version)
            return subprocess.CompletedProcess(cmd, 0)
        return subprocess.run(cmd, **kw)


def no_net(*a, **kw):
    raise AssertionError("network used")


def test_install_cargo(home):
    run = Runner()
    msg = fetter_bin.install(home, run=run, which=lambda n: "/c/cargo", urlopen_=no_net)
    assert "crates.io" in msg
    cargo = run.calls[0]
    assert cargo[:6] == ["/c/cargo", "install", "fetter", "--version", "=5.1.0", "--locked"]
    assert cargo[6] == "--root" and Path(cargo[7]).parent == home.root
    assert fetter_bin.probe(home.fetter).version == (5, 1, 0)
    assert [p.name for p in home.root.iterdir()] == ["bin"]   # staging removed


def test_install_noop_when_current(home):
    fake_fetter(home.fetter, "5.1.0")
    run = Runner()
    msg = fetter_bin.install(home, run=run, which=lambda n: "/c/cargo", urlopen_=no_net)
    assert "already installed" in msg
    assert not any(c[1:2] == ["install"] for c in run.calls)


def test_install_replaces_old_and_force(home):
    fake_fetter(home.fetter, "4.0.0")
    run = Runner()
    fetter_bin.install(home, run=run, which=lambda n: "/c/cargo", urlopen_=no_net)
    assert fetter_bin.probe(home.fetter).version == (5, 1, 0)
    run = Runner()
    fetter_bin.install(home, force=True, run=run, which=lambda n: "/c/cargo", urlopen_=no_net)
    assert any(c[1:2] == ["install"] for c in run.calls)


def test_install_cargo_fails_keeps_existing(home):
    fake_fetter(home.fetter, "4.0.0")
    with pytest.raises(InstallError, match="cargo install failed"):
        fetter_bin.install(home, run=Runner(fail=True), which=lambda n: "/c/cargo")
    assert fetter_bin.probe(home.fetter).version == (4, 0, 0)
    assert sorted(p.name for p in home.root.iterdir()) == ["bin"]


def test_install_wrong_version(home):
    with pytest.raises(InstallError, match="expected 5.1.0"):
        fetter_bin.install(home, run=Runner("5.1.1"), which=lambda n: "/c/cargo")
    assert not home.fetter.exists()


def test_install_cargo_method_without_cargo(home):
    with pytest.raises(InstallError, match="cargo is not on PATH"):
        fetter_bin.install(home, method="cargo", which=lambda n: None)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def make_wheel(script=FAKE_SCRIPT, member="fetter-5.1.0.data/scripts/fetter") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fetter-5.1.0.dist-info/METADATA", "Name: fetter\n")
        zf.writestr(member, script)
    return buf.getvalue()


def pypi(wheel: bytes, digest=None, status=200):
    meta = {"urls": [
        {"packagetype": "sdist", "filename": "fetter-5.1.0.tar.gz", "url": "https://f/sdist"},
        {"packagetype": "bdist_wheel", "filename": "fetter-5.1.0-py3-none-otherplat.whl",
         "url": "https://f/other", "digests": {"sha256": "0"}},
        {"packagetype": "bdist_wheel", "filename": "fetter-5.1.0-py3-none-testplat.whl",
         "url": "https://f/wheel",
         "digests": {"sha256": digest or hashlib.sha256(wheel).hexdigest()}},
    ]}
    seen = []

    def urlopen_(req, timeout):
        seen.append(req.full_url)
        if req.full_url.startswith("https://pypi.org/"):
            if status != 200:
                raise HTTPError(req.full_url, status, "x", {}, None)
            return FakeResponse(json.dumps(meta).encode())
        assert req.full_url == "https://f/wheel"
        return FakeResponse(wheel)
    urlopen_.seen = seen
    return urlopen_


@pytest.fixture
def testplat(monkeypatch):
    monkeypatch.setattr(fetter_bin, "_platform_matches", lambda tag: tag == "testplat")


def test_install_pypi_fallback(home, testplat):
    u = pypi(make_wheel())
    msg = fetter_bin.install(home, run=Runner(), which=lambda n: None, urlopen_=u)
    assert "PyPI" in msg
    assert u.seen == ["https://pypi.org/pypi/fetter/5.1.0/json", "https://f/wheel"]
    assert fetter_bin.probe(home.fetter).version == (5, 1, 0)


def test_install_pypi_method_skips_cargo(home, testplat):
    run = Runner()
    fetter_bin.install(home, method="pypi", run=run, which=lambda n: "/c/cargo",
                       urlopen_=pypi(make_wheel()))
    assert not any(c[1:2] == ["install"] for c in run.calls)


def test_install_pypi_not_published(home, testplat):
    with pytest.raises(InstallError, match="not on PyPI .*rustup"):
        fetter_bin.install(home, which=lambda n: None, urlopen_=pypi(b"", status=404))
    assert not home.fetter.exists()


def test_install_pypi_bad_digest(home, testplat):
    with pytest.raises(InstallError, match="sha256"):
        fetter_bin.install(home, which=lambda n: None, urlopen_=pypi(make_wheel(), digest="ab"))


def test_install_pypi_no_binary_in_wheel(home, testplat):
    w = make_wheel(member="fetter/__init__.py")
    with pytest.raises(InstallError, match="no fetter binary"):
        fetter_bin.install(home, which=lambda n: None, urlopen_=pypi(w))


def test_install_pypi_no_wheel_for_platform(home, monkeypatch):
    monkeypatch.setattr(fetter_bin, "_platform_matches", lambda tag: False)
    with pytest.raises(InstallError, match="no fetter 5.1.0 wheel"):
        fetter_bin.install(home, which=lambda n: None, urlopen_=pypi(make_wheel()))


@pytest.mark.parametrize("plat,machine,libc,tag,expect", [
    ("linux", "x86_64", "glibc", "manylinux_2_17_x86_64.manylinux2014_x86_64", True),
    ("linux", "x86_64", "glibc", "musllinux_1_2_x86_64", False),
    ("linux", "x86_64", "", "musllinux_1_2_x86_64", True),
    ("linux", "aarch64", "glibc", "manylinux_2_17_x86_64", False),
    ("linux", "aarch64", "glibc", "manylinux_2_17_aarch64.manylinux2014_aarch64", True),
    ("darwin", "arm64", "", "macosx_11_0_arm64", True),
    ("darwin", "x86_64", "", "macosx_10_12_x86_64", True),
    ("darwin", "x86_64", "", "macosx_10_12_universal2", True),
    ("darwin", "x86_64", "", "macosx_11_0_arm64", False),
    ("win32", "AMD64", "", "win_amd64", True),
    ("win32", "ARM64", "", "win_amd64", False),
])
def test_platform_matches(monkeypatch, plat, machine, libc, tag, expect):
    monkeypatch.setattr(fetter_bin.sys, "platform", plat)
    monkeypatch.setattr(fetter_bin.platform, "machine", lambda: machine)
    monkeypatch.setattr(fetter_bin.platform, "libc_ver", lambda: (libc, ""))
    assert fetter_bin._platform_matches(tag) is expect


def test_install_unwritable_home(tmp_path):
    from fetter_scope.home import Home
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o500)
    with pytest.raises(InstallError, match="cannot write"):
        fetter_bin.install(Home(ro / "home"), which=lambda n: None, urlopen_=no_net)
