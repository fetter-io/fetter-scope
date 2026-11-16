import base64
import io
import json
import smtplib
from urllib.error import HTTPError, URLError

from fetter_scope import delivery
from fetter_scope.config import Credentials
from fetter_scope.delivery import Attachment, Message, Transports

PM = Credentials(email_from="scope@x.org", email_to=("a@x.org", "b@x.org"),
                 postmark_token="tok")
SMTP = Credentials(email_from="scope@x.org", email_to=("a@x.org",), smtp_host="mail.x.org",
                   smtp_port=587, smtp_user="u", smtp_password="secret")
MSG = Message("fetter host · ALERT", "<p>hi</p>", "hi\n",
              (Attachment("d.json", b'{"a": 1}'),))


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def recorder(fail=None):
    calls = []

    def urlopen(req, timeout):
        calls.append(req)
        if fail:
            raise fail
        return Resp(b"{}")
    return urlopen, calls


def test_postmark_send():
    urlopen, calls = recorder()
    r = delivery.send(MSG, "postmark", PM, Transports(urlopen=urlopen))
    assert r.ok and r.status == "sent"
    [req] = calls
    assert req.full_url == "https://api.postmarkapp.com/email" and req.get_method() == "POST"
    assert req.get_header("X-postmark-server-token") == "tok"
    body = json.loads(req.data)
    assert body["To"] == "a@x.org, b@x.org" and body["From"] == "scope@x.org"
    assert (body["Subject"], body["HtmlBody"], body["TextBody"]) == (MSG.subject, MSG.html, MSG.text)
    [att] = body["Attachments"]
    assert att["Name"] == "d.json" and base64.b64decode(att["Content"]) == b'{"a": 1}'


def test_postmark_http_error():
    err = HTTPError("u", 422, "x", {}, io.BytesIO(b'{"ErrorCode": 300, "Message": "Invalid From"}'))
    urlopen, _ = recorder(err)
    r = delivery.send(MSG, "postmark", PM, Transports(urlopen=urlopen))
    assert r.status == "failed" and r.error == "Postmark: HTTP 422: Invalid From"
    assert "tok" not in r.error


def test_postmark_network_error():
    urlopen, _ = recorder(URLError("no route"))
    assert delivery.send(MSG, "postmark", PM, Transports(urlopen=urlopen)).error == "Postmark: no route"


def test_skipped_when_not_configured():
    r = delivery.send(MSG, "postmark", Credentials(), Transports(urlopen=None))
    assert r.status == "skipped" and "POSTMARK_SERVER_TOKEN" in r.error
    assert delivery.send(MSG, "smtp", PM).status == "skipped"


def test_postmark_verify():
    urlopen, calls = recorder()
    assert delivery.verify("postmark", PM, Transports(urlopen=urlopen)).ok
    assert calls[0].full_url.endswith("/server") and calls[0].get_method() == "GET"


class FakeSMTP:
    instances = []

    def __init__(self, host, port, timeout=None, context=None, fail_login=False):
        self.host, self.port, self.context, self.calls = host, port, context, []
        self.fail_login = fail_login
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user))
        if self.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    def send_message(self, msg):
        self.calls.append(("send", msg))

    def quit(self):
        self.calls.append("quit")


def smtp_transports(**kw):
    FakeSMTP.instances = []
    make = lambda *a, **k: FakeSMTP(*a, **k, **kw)
    return Transports(smtp=make, smtp_ssl=make)


def test_smtp_starttls_send():
    r = delivery.send(MSG, "smtp", SMTP, smtp_transports())
    assert r.ok
    [s] = FakeSMTP.instances
    assert (s.host, s.port, s.context) == ("mail.x.org", 587, None)
    assert s.calls[:4] == ["ehlo", "starttls", "ehlo", ("login", "u")] and s.calls[-1] == "quit"
    msg = s.calls[4][1]
    assert msg["To"] == "a@x.org" and msg["Subject"] == MSG.subject
    parts = [(p.get_content_type(), p.get_filename()) for p in msg.walk()]
    assert ("text/plain", None) in parts and ("text/html", None) in parts
    assert ("application/json", "d.json") in parts


def test_smtp_ssl_without_login():
    creds = Credentials(**{**SMTP.__dict__, "smtp_tls": "ssl", "smtp_user": "", "smtp_port": 465})
    assert delivery.send(MSG, "smtp", creds, smtp_transports()).ok
    [s] = FakeSMTP.instances
    assert s.context is not None and "starttls" not in s.calls
    assert not any(isinstance(c, tuple) and c[0] == "login" for c in s.calls)


def test_smtp_auth_failure():
    r = delivery.send(MSG, "smtp", SMTP, smtp_transports(fail_login=True))
    assert r.status == "failed" and r.error == "SMTP: authentication failed (535)"
    assert "secret" not in r.error


def test_smtp_connection_error():
    def refuse(*a, **k):
        raise ConnectionRefusedError(111, "Connection refused")
    r = delivery.send(MSG, "smtp", SMTP, Transports(smtp=refuse))
    assert r.status == "failed" and "Connection refused" in r.error


def test_smtp_verify_sends_nothing():
    assert delivery.verify("smtp", SMTP, smtp_transports()).ok
    [s] = FakeSMTP.instances
    assert not any(isinstance(c, tuple) and c[0] == "send" for c in s.calls)
    assert s.calls[-1] == "quit"
