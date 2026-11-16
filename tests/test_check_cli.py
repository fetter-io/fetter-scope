from fetter_scope.__main__ import main

from tests.conftest import fake_fetter


def run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_check_ok(home, capsys, monkeypatch):
    for k in ("REPORT_EMAIL_FROM", "REPORT_EMAIL_TO", "POSTMARK_SERVER_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    fake_fetter(home.fetter, "5.0.0")
    home.config.write_text("[fetter]\nperiod = 60\n")
    code, out = run(capsys, "check", "--home", str(home.root))
    assert code == 0, out
    assert f"fetter:  {home.fetter} (fetter-scope's own), version 5.0.0" in out
    assert "mail:    disabled" in out
    assert f"{home.fetter} monitor-diff --period 60 --report-period 60 --control stdin json" in out


def test_check_missing_binary_and_errors(home, capsys):
    home.root.mkdir(parents=True)
    home.config.write_text("[fetter]\nperiod = -1\n[mail]\nenabled = true\n")
    code, out = run(capsys, "--home", str(home.root), "check")
    assert code == 1
    assert "error: [fetter] period" in out
    assert "run `fetter-scope install-fetter`" in out
    assert "mail not configured" in out


def test_check_old_configured_binary(home, tmp_path, capsys):
    old = fake_fetter(tmp_path / "old" / "fetter", "3.1.0")
    home.root.mkdir(parents=True)
    home.config.write_text(f'[fetter]\nbinary = "{old}"\n')
    code, out = run(capsys, "check", "--home", str(home.root))
    assert code == 1
    assert "is fetter 3.1.0" in out and "[fetter] binary" in out




def test_run_refuses_config_errors(home, capsys):
    fake_fetter(home.fetter)
    home.config.write_text("[fetter]\nperiod = 0\n")
    assert main(["run", "--headless", "--home", str(home.root)]) == 1
    assert "has errors" in capsys.readouterr().err


def test_run_refuses_old_fetter(home, capsys):
    fake_fetter(home.fetter, "4.0.0")
    assert main(["run", "--headless", "--home", str(home.root)]) == 1
    assert "requires 5.0.0" in capsys.readouterr().err


def test_run_refuses_missing_fetter(home, capsys):
    assert main(["run", "--headless", "--home", str(home.root)]) == 1
    assert "install-fetter" in capsys.readouterr().err


def test_attach_missing_file(tmp_path, capsys):
    assert main(["attach", str(tmp_path / "nope.jsonl")]) == 1


# digest ---------------------------------------------------------------------------

import json  # noqa: E402
from pathlib import Path  # noqa: E402

from fetter_scope.events import parse_line  # noqa: E402
from fetter_scope.store import Store  # noqa: E402

STREAMS = Path(__file__).parent / "fixtures" / "streams"


def stored(home):
    lines = (STREAMS / "changes.jsonl").read_text().splitlines()
    t = json.loads(lines[0])["time"]["secs"]
    store = Store(home, now=lambda: t)
    for line in lines:
        store.append(parse_line(line))
    store.close()
    return t


def test_digest_preview(home, capsys):
    stored(home)
    assert main(["digest", "--home", str(home.root)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Subject: fetter host · ALERT · 3 new vulns · 1 downgrade · 2 changes")
    assert "Downgrades" in out and "attached as JSON" not in out


def test_digest_json_since_last_digest(home, capsys):
    t = stored(home)
    assert main(["digest", "--json", "--home", str(home.root)]) == 0
    assert json.loads(capsys.readouterr().out)["reports"] == 1
    Store(home).update_state(digest={"last_end": t + 3600})
    assert main(["digest", "--json", "--home", str(home.root)]) == 0
    assert "nothing recorded" in capsys.readouterr().out


def test_digest_html(home, capsys, monkeypatch):
    stored(home)
    opened = []
    monkeypatch.setattr("webbrowser.open", opened.append)
    assert main(["digest", "--html", "--home", str(home.root)]) == 0
    path = Path(capsys.readouterr().out.strip())
    try:
        assert opened == [path.as_uri()] and path.read_text().startswith("<!doctype html>")
    finally:
        path.unlink()


def test_digest_nothing(home, capsys):
    assert main(["digest", "--home", str(home.root)]) == 0
    assert "nothing recorded" in capsys.readouterr().out


def test_tui_refuses_missing_fetter(home, capsys):
    assert main(["--home", str(home.root)]) == 1
    assert main(["run", "--home", str(home.root)]) == 1
    assert "install-fetter" in capsys.readouterr().err
