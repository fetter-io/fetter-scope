from pathlib import Path

from fetter_scope import home as home_mod
from fetter_scope.home import Home


def test_default_root(monkeypatch, tmp_path):
    monkeypatch.delenv("FETTER_SCOPE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    h = Home.locate()
    assert h.root == tmp_path / ".fetter-scope"
    assert h.config == h.root / "config.toml"
    assert h.env == h.root / ".env"
    assert h.events == h.root / "events"
    assert h.mail == h.root / "mail"
    assert h.state == h.root / "state.json"


def test_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("FETTER_SCOPE_HOME", str(tmp_path / "e"))
    assert Home.locate().root == tmp_path / "e"


def test_arg_wins_over_env(monkeypatch, tmp_path):
    monkeypatch.setenv("FETTER_SCOPE_HOME", str(tmp_path / "e"))
    assert Home.locate(tmp_path / "a").root == tmp_path / "a"


def test_binary_name(monkeypatch, tmp_path):
    h = Home(tmp_path)
    monkeypatch.setattr(home_mod.sys, "platform", "linux")
    assert h.fetter == tmp_path / "bin" / "fetter"
    monkeypatch.setattr(home_mod.sys, "platform", "win32")
    assert h.fetter == tmp_path / "bin" / "fetter.exe"


def test_ensure_mode(tmp_path):
    h = Home(tmp_path / "h")
    assert not h.root.exists()
    h.ensure()
    assert h.root.is_dir()
    assert h.root.stat().st_mode & 0o777 == 0o700
