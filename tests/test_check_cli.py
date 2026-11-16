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


def test_unimplemented(capsys, home):
    assert main(["--home", str(home.root)]) == 2
    assert "milestone 5" in capsys.readouterr().err
