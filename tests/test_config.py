import pytest

from fetter_scope import config
from fetter_scope.config import parse_duration, parse_time_of_day

SPEC_EXAMPLE = """
[fetter]
binary = "~/bin/fetter"
args = ["-E", "python,npm", "--root", "~/src"]
period = 120
report_period = 600
report = "always"
baseline = "~/base.json"
bound = "~/req.txt"
bound_options = ["dev"]
subset = true
cvss = 7.5

[mail]
enabled = true
transport = "smtp"
every = "7d"
at = "06:30"
weekday = "mon"
send_unchanged = true
alerts = "digest"
alert_min_interval = "1h"
subject_prefix = "box"

[tui]
theme = "nord"
feed_limit = 100

[store]
retention_days = 30
"""


def load(home, text=None, environ=None):
    if text is not None:
        home.root.mkdir(parents=True, exist_ok=True)
        home.config.write_text(text)
    return config.load(home, environ={} if environ is None else environ)


def test_defaults_without_file(home):
    c = load(home)
    assert not c.found and c.errors == ()
    assert c.fetter == config.FetterConfig()
    assert c.mail == config.MailConfig()
    assert c.fetter.period == 300 and c.fetter.report_period == 300
    assert c.mail.every == 86400 and c.mail.at == (7, 0) and c.mail.alert_min_interval == 900
    assert c.store.retention_days == 90


def test_full_example(home):
    c = load(home, SPEC_EXAMPLE)
    assert c.found and c.errors == ()
    f = c.fetter
    assert f.binary == "~/bin/fetter"
    assert f.args == ("-E", "python,npm", "--root", "~/src")
    assert (f.period, f.report_period, f.report) == (120, 600, "always")
    assert f.bound_options == ("dev",) and f.subset and not f.strict
    assert f.cvss == 7.5
    m = c.mail
    assert m.enabled and m.transport == "smtp" and m.every == 7 * 86400
    assert m.at == (6, 30) and m.weekday == "mon" and m.send_unchanged
    assert m.alerts == "digest" and m.alert_min_interval == 3600 and m.subject_prefix == "box"
    assert c.tui == config.TuiConfig(theme="nord", feed_limit=100)
    assert c.store.retention_days == 30


def test_report_period_defaults_to_period(home):
    c = load(home, "[fetter]\nperiod = 60\n")
    assert c.fetter.report_period == 60


def test_errors_collected_with_defaults(home):
    c = load(home, """
[fetter]
period = 0
cvss = 11
args = "x"
subset = 1
colour = 1

[mail]
every = "daily"
at = "7am"
weekday = "funday"
transport = "pigeon"
enabled = "yes"

[other]
x = 1
""")
    text = "\n".join(c.errors)
    for needle in ("[fetter] period: expected above 0", "[fetter] cvss: expected 0 to 10",
                   "[fetter] args: expected list", "[fetter] subset: expected bool",
                   "[fetter] colour: unknown key", "[mail] every:", "[mail] at:",
                   "[mail] weekday: expected one of", "[mail] transport: expected one of",
                   "[mail] enabled: expected bool", "[other]: unknown table"):
        assert needle in text, needle
    assert c.fetter == config.FetterConfig()
    assert c.mail == config.MailConfig()


def test_weekday_requires_weekly(home):
    c = load(home, '[mail]\nevery = "1d"\nweekday = "mon"\n')
    assert any("only applies" in e for e in c.errors)


def test_bad_toml(home):
    c = load(home, "[fetter\n")
    assert c.found and len(c.errors) == 1
    assert c.fetter == config.FetterConfig()


def test_explicit_missing_config(home, tmp_path):
    c = config.load(home, tmp_path / "nope.toml", environ={})
    assert c.errors and "not found" in c.errors[0]


def test_env_file_and_process_env(home):
    home.root.mkdir(parents=True)
    home.env.write_text("REPORT_EMAIL_FROM=a@x.org\nREPORT_EMAIL_TO=b@x.org, c@x.org\n"
                        "POSTMARK_SERVER_TOKEN=from-file\n")
    c = load(home, '[mail]\nenabled = true\n', environ={"POSTMARK_SERVER_TOKEN": "from-env"})
    cr = c.credentials
    assert cr.email_from == "a@x.org"
    assert cr.email_to == ("b@x.org", "c@x.org")
    assert cr.postmark_token == "from-env"
    assert c.mail_missing == []


def test_env_beside_explicit_config(home, tmp_path):
    d = tmp_path / "elsewhere"
    d.mkdir()
    (d / "config.toml").write_text("")
    (d / ".env").write_text("SMTP_HOST=mail.example\nSMTP_PORT=465\nSMTP_TLS=ssl\n")
    c = config.load(home, d / "config.toml", environ={})
    assert (c.credentials.smtp_host, c.credentials.smtp_port, c.credentials.smtp_tls) == \
        ("mail.example", 465, "ssl")


def test_missing_credentials(home):
    c = load(home, '[mail]\nenabled = true\ntransport = "smtp"\n')
    assert c.mail_missing == ["REPORT_EMAIL_FROM", "REPORT_EMAIL_TO", "SMTP_HOST"]


def test_bad_smtp_env(home):
    c = load(home, environ={"SMTP_PORT": "x", "SMTP_TLS": "tls1"})
    assert len(c.errors) == 2 and c.credentials.smtp_port == 587


@pytest.mark.parametrize("s,secs", [("30s", 30), ("15m", 900), ("6h", 21600), ("1d", 86400),
                                    (" 7d ", 604800)])
def test_parse_duration(s, secs):
    assert parse_duration(s) == secs


@pytest.mark.parametrize("s", ["0m", "1w", "h", "", "1.5h", 5])
def test_parse_duration_bad(s):
    with pytest.raises(ValueError):
        parse_duration(s)


def test_parse_time_of_day():
    assert parse_time_of_day("00:00") == (0, 0)
    assert parse_time_of_day("23:59") == (23, 59)
    for bad in ("24:00", "7:00", "07:60", "0700"):
        with pytest.raises(ValueError):
            parse_time_of_day(bad)
