"""Send mail through Postmark (urllib) or SMTP (smtplib); both stdlib.

`send` never raises: it returns a `Result` of sent, failed (with the error) or skipped (mail
not configured). `verify` is `check`'s dry run: it authenticates without sending anything.
Credentials are never logged or included in an error.
"""
import base64
import json
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fetter_scope import __version__
from fetter_scope.config import Credentials

POSTMARK_URL = "https://api.postmarkapp.com"
TIMEOUT = 30.0

SENT, FAILED, SKIPPED = "sent", "failed", "skipped"


@dataclass(frozen=True)
class Attachment:
    name: str
    content: bytes
    content_type: str = "application/json"


@dataclass(frozen=True)
class Message:
    subject: str
    html: str
    text: str
    attachments: tuple[Attachment, ...] = ()


@dataclass(frozen=True)
class Result:
    status: str                       # SENT, FAILED or SKIPPED
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == SENT


@dataclass
class Transports:
    """The network entry points, replaceable in tests."""
    urlopen: Callable = urlopen
    smtp: Callable = smtplib.SMTP
    smtp_ssl: Callable = smtplib.SMTP_SSL


def _postmark_request(path: str, token: str, payload: dict | None = None) -> Request:
    headers = {"Accept": "application/json", "X-Postmark-Server-Token": token,
               "User-Agent": f"fetter-scope/{__version__}"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode()
    return Request(POSTMARK_URL + path, data=data, method="POST" if data else "GET",
                   headers=headers)


def _http_error(e: HTTPError) -> str:
    try:
        detail = json.loads(e.read() or b"{}").get("Message", "")
    except (ValueError, OSError, AttributeError):
        detail = ""
    return f"HTTP {e.code}" + (f": {detail}" if detail else "")


def _send_postmark(m: Message, creds: Credentials, t: Transports) -> None:
    payload = {
        "From": creds.email_from, "To": ", ".join(creds.email_to), "Subject": m.subject,
        "HtmlBody": m.html, "TextBody": m.text, "MessageStream": "outbound",
    }
    if m.attachments:
        payload["Attachments"] = [{"Name": a.name, "ContentType": a.content_type,
                                   "Content": base64.b64encode(a.content).decode()}
                                  for a in m.attachments]
    with t.urlopen(_postmark_request("/email", creds.postmark_token, payload), timeout=TIMEOUT) as r:
        r.read()


def _smtp_connect(creds: Credentials, t: Transports):
    context = ssl.create_default_context()
    if creds.smtp_tls == "ssl":
        server = t.smtp_ssl(creds.smtp_host, creds.smtp_port, timeout=TIMEOUT, context=context)
    else:
        server = t.smtp(creds.smtp_host, creds.smtp_port, timeout=TIMEOUT)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
    if creds.smtp_user:
        server.login(creds.smtp_user, creds.smtp_password)
    return server


def email_message(m: Message, creds: Credentials) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = creds.email_from
    msg["To"] = ", ".join(creds.email_to)
    msg["Subject"] = m.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=creds.email_from.rpartition("@")[2] or None)
    msg.set_content(m.text)
    msg.add_alternative(m.html, subtype="html")
    for a in m.attachments:
        maintype, _, subtype = a.content_type.partition("/")
        msg.add_attachment(a.content, maintype=maintype, subtype=subtype or "octet-stream",
                           filename=a.name)
    return msg


def _send_smtp(m: Message, creds: Credentials, t: Transports) -> None:
    server = _smtp_connect(creds, t)
    try:
        server.send_message(email_message(m, creds))
    finally:
        try:
            server.quit()
        except (smtplib.SMTPException, OSError):
            pass


def _attempt(transport: str, action: Callable[[], None]) -> Result:
    try:
        action()
    except HTTPError as e:
        return Result(FAILED, f"Postmark: {_http_error(e)}")
    except URLError as e:
        return Result(FAILED, f"Postmark: {e.reason}")
    except smtplib.SMTPAuthenticationError as e:
        return Result(FAILED, f"SMTP: authentication failed ({e.smtp_code})")
    except smtplib.SMTPException as e:
        return Result(FAILED, f"SMTP: {e}")
    except (OSError, ssl.SSLError, TimeoutError) as e:
        return Result(FAILED, f"{transport}: {e}")
    return Result(SENT)


def _ready(transport: str, creds: Credentials) -> Result | None:
    if missing := creds.missing(transport):
        return Result(SKIPPED, f"mail not configured: {', '.join(missing)} not set")
    if transport not in ("postmark", "smtp"):
        return Result(FAILED, f"unknown transport {transport!r}")
    return None


def send(m: Message, transport: str, creds: Credentials, t: Transports | None = None) -> Result:
    """Send `m`; never raises."""
    t = t or Transports()
    if (not_ready := _ready(transport, creds)) is not None:
        return not_ready
    if transport == "postmark":
        return _attempt(transport, lambda: _send_postmark(m, creds, t))
    return _attempt(transport, lambda: _send_smtp(m, creds, t))


def verify(transport: str, creds: Credentials, t: Transports | None = None) -> Result:
    """Check the credentials without sending: Postmark's server endpoint, or an SMTP login."""
    t = t or Transports()
    if (not_ready := _ready(transport, creds)) is not None:
        return not_ready

    def postmark():
        with t.urlopen(_postmark_request("/server", creds.postmark_token), timeout=TIMEOUT) as r:
            r.read()

    def smtp():
        server = _smtp_connect(creds, t)
        try:
            server.quit()
        except (smtplib.SMTPException, OSError):
            pass

    return _attempt(transport, postmark if transport == "postmark" else smtp)
