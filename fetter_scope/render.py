"""A digest (see `digest.fold`) as an email: subject, HTML with inline styles, and text.

Both bodies are built from one section model, so they say the same things in the same order:
alerts (new vulnerabilities by CVSS, new hooks, downgrades, new violations, the alert reports),
problems, transient items, package changes by ecosystem and site, then what was resolved.

Email clients drop `<style>`, classes and SVG, so every style is inline. The HTML stays under
Gmail's ~102 KB clipping limit: `fit` cuts long lists ("and N more") until it does; the full
digest travels as a JSON attachment.
"""
import html
import time
from dataclasses import dataclass, field

from fetter_scope import __version__

HTML_LIMIT = 100_000                     # bytes; Gmail clips at about 102 KB
CAPS = (None, 200, 100, 50, 20, 10, 5)   # items per list, tried in turn
HOOK_DETAIL_LIMIT = 600                  # characters of a hook's code shown in mail

C = {"fg": "#1d1d1f", "muted": "#6e6e73", "line": "#e3e3e8", "panel": "#f6f6f8",
     "bad": "#c62828", "warn": "#9a6700", "good": "#1a7f37", "accent": "#3557a6"}
FONT = '-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif'
MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'


@dataclass
class Item:
    title: str
    meta: str = ""                       # muted: where and when
    detail: str = ""                     # a sentence, e.g. a vulnerability summary
    url: str = ""
    code: str = ""                       # shown verbatim (a hook's content), never run
    tone: str = ""                       # "bad", "warn", "good", or ""


@dataclass
class Section:
    title: str
    items: list[Item] = field(default_factory=list)
    level: int = 3                       # 2: a top heading; 3: a list under it
    tone: str = ""


#-------------------------------------------------------------------------------
# formatting

def when(t: float | None) -> str:
    return "?" if t is None else time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def span(a: float | None, b: float | None) -> str:
    if a is None or b is None or when(a) == when(b):
        return when(a if a is not None else b)
    da, db = when(a), when(b)
    return f"{da}–{db[11:]}" if da[:10] == db[:10] else f"{da} – {db}"


def plural(n: int, word: str, many: str = "") -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _pkg(p: dict | None) -> str:
    return "" if not p else f"{p.get('name', p.get('key', '?'))} {p.get('version', '')}".strip()


def _where(eco: str | None, site: str | None) -> str:
    return " · ".join(x for x in (eco, site) if x)


#-------------------------------------------------------------------------------
# the section model

def subject(d: dict, prefix: str = "fetter") -> str:
    c = d["counts"]
    parts = [f"{prefix} {d.get('system', {}).get('hostname') or '?'}".strip()]
    if d["status"] == "alert":
        parts.append("ALERT")
    for n, word in ((c["new_vulns"], "new vuln"), (c["new_hooks"], "hook"),
                    (c["downgrades"], "downgrade"), (c["new_violations"], "violation"),
                    (c["changes"], "change"), (c["problems"], "problem")):
        if n:
            parts.append(plural(n, word))
    if len(parts) == 1:                  # no counts: a heartbeat, or only transient items
        parts.append(d["status"] if c["eventful"] else "unchanged")
    return " · ".join(parts)


def _alerts(d: dict) -> list[Section]:
    out = []
    vulns = [Item(
        title=f"{v.get('id', '?')}" + (f"  CVSS {v['score']:g}" if v.get("score") is not None else ""),
        meta=" · ".join(x for x in ((v.get("package") or {}).get("ecosystem"),
                                     _pkg(v.get("package")), v.get("source"),
                                     "mailed" if v.get("mailed") else "") if x),
        detail=v.get("summary", ""), url=v.get("url", ""), tone="bad")
        for v in d["vulns"]["new"]]
    if vulns:
        out.append(Section("New vulnerabilities", vulns, tone="bad"))
    hooks = [Item(title=(h.get("hook") or {}).get("name", "?"),
                  meta=f"{_where(h.get('ecosystem'), h.get('site'))} · {when(h.get('first'))}"
                       + _mailed(h),
                  code=_clip((h.get("hook") or {}).get("detail", ""), HOOK_DETAIL_LIMIT), tone="bad")
             for h in d["hooks"]["added"]]
    if hooks:
        out.append(Section("New hooks", hooks, tone="bad"))
    downs = [Item(title=f"{p['name']} {(p.get('from') or {}).get('version', '?')} → "
                        f"{(p.get('to') or {}).get('version', '?')}",
                  meta=f"{_where(p['ecosystem'], p['site'])} · {when(p.get('last'))}" + _mailed(p),
                  tone="bad")
             for p in d["packages"] if p["change"] == "downgraded"]
    if downs:
        out.append(Section("Downgrades", downs, tone="bad"))
    viol = [_violation_item(v, "bad") for v in d["violations"]["new"]]
    for it, v in zip(viol, d["violations"]["new"]):
        it.meta += _mailed(v)
    if viol:
        out.append(Section("New allow-list violations", viol, tone="bad"))
    reports = [Item(title=when(r["time"]),
                    meta=", ".join(plural(r[k], w) for k, w in (
                        ("new_vulns", "new vuln"), ("new_hooks", "new hook"),
                        ("downgrades", "downgrade"), ("new_violations", "new violation")) if r.get(k)))
               for r in d["alert_reports"]]
    if reports:
        out.append(Section("Alert reports", reports))
    return out


def _mailed(x: dict) -> str:
    return " · mailed" if x.get("mailed") else ""


def _violation_item(v: dict, tone: str) -> Item:
    who = " ".join(x for x in (v.get("package"), v.get("dependency") and f"(requires {v['dependency']})") if x)
    sites = ", ".join(v.get("sites") or [])
    return Item(title=v.get("explain", "?"),
                meta=" · ".join(x for x in (v.get("ecosystem"), who, sites) if x), tone=tone)


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + f"\n… ({len(s) - n} more characters)"


def _problems(d: dict) -> list[Section]:
    items = [Item(title=p["message"],
                  meta=(span(p["time"], p["until"]) if p.get("until") else when(p["time"]))
                       + f" · {p['kind']}", tone="warn")
             for p in d["problems"]]
    return [Section("Problems", items, level=2, tone="warn")] if items else []


def _transient(d: dict) -> list[Section]:
    t = d["transient"]
    items = []
    for p in t["packages"]:
        items.append(Item(title=f"{p['name']}: {' → '.join(p.get('versions') or [])}",
                          meta=f"{p['what']}, {span(p.get('first'), p.get('last'))} · "
                               f"{_where(p.get('ecosystem'), p.get('site'))}"))
    for cat, label in (("origins", "origin"), ("sites", "site")):
        for o in t[cat]:
            verb = "added then removed" if o.get("change") == "added" else "removed then restored"
            items.append(Item(title=f"{label} {o.get('path', '?')}",
                              meta=f"{verb}, {span(o.get('first'), o.get('last'))} · {o.get('ecosystem', '')}"))
    for h in t["hooks"]:
        verb = "added then removed" if h.get("change") == "added" else "removed then restored"
        items.append(Item(title=f"hook {(h.get('hook') or {}).get('name', '?')}",
                          meta=f"{verb}, {span(h.get('first'), h.get('last'))} · "
                               f"{_where(h.get('ecosystem'), h.get('site'))}",
                          code=_clip((h.get("hook") or {}).get("detail", ""), HOOK_DETAIL_LIMIT)))
    for v in t["vulns"]:
        items.append(Item(title=f"{v.get('id', '?')} in {_pkg(v.get('package'))}",
                          meta=f"{v.get('what', '')}, {span(v.get('first'), v.get('last'))}",
                          url=v.get("url", "")))
    for v in t["violations"]:
        it = _violation_item(v, "")
        it.meta = f"new then resolved, {span(v.get('first'), v.get('last'))} · {it.meta}"
        items.append(it)
    return [Section("Transient", items, level=2)] if items else []


def _changes(d: dict) -> list[Section]:
    out = []
    groups: dict[tuple, list[Item]] = {}
    for p in d["packages"]:
        frm, to = (p.get("from") or {}).get("version"), (p.get("to") or {}).get("version")
        versions = f"{frm} → {to}" if frm and to else (to or frm or "")
        tone = "bad" if p["change"] == "downgraded" else ""
        groups.setdefault((p["ecosystem"], p["site"]), []).append(
            Item(title=f"{p['change']} {p['name']} {versions}".strip(),
                 meta=when(p.get("last")), tone=tone))
    if groups or any(d[k][x] for k in ("origins", "sites") for x in ("added", "removed")):
        out.append(Section("Changes", level=2))
    for (eco, site), items in groups.items():
        out.append(Section(_where(eco, site), items))
    os_items = []
    for cat, label in (("origins", "origin"), ("sites", "site")):
        for change in ("added", "removed"):
            for o in d[cat][change]:
                os_items.append(Item(title=f"{change} {label} {o.get('path', '?')}",
                                     meta=f"{o.get('ecosystem', '')} · {when(o.get('last'))}"))
    if os_items:
        out.append(Section("Origins and sites", os_items))
    return out


def _resolved(d: dict) -> list[Section]:
    out = []
    v = [Item(title=f"{x.get('id', '?')} in {_pkg(x.get('package'))}", meta=when(x.get("last")),
              tone="good") for x in d["vulns"]["resolved"]]
    h = [Item(title=(x.get("hook") or {}).get("name", "?"),
              meta=f"{_where(x.get('ecosystem'), x.get('site'))} · {when(x.get('last'))}")
         for x in d["hooks"]["removed"]]
    x_ = [_violation_item(x, "good") for x in d["violations"]["resolved"]]
    if v or h or x_:
        out.append(Section("Resolved", level=2))
    for title, items in (("Resolved vulnerabilities", v), ("Removed hooks", h),
                         ("Resolved allow-list violations", x_)):
        if items:
            out.append(Section(title, items))
    return out


def sections(d: dict, alerts_only: bool = False) -> list[Section]:
    alerts = _alerts(d)
    head = [Section("Alerts", level=2, tone="bad")] if alerts else []
    if alerts_only:
        return head + alerts
    return head + alerts + _problems(d) + _transient(d) + _changes(d) + _resolved(d)


def headline(d: dict) -> str:
    c = d["counts"]
    bits = []
    for key, one, many in (("new_vulns", "new vulnerability", "new vulnerabilities"),
                           ("new_hooks", "new hook", ""), ("downgrades", "downgrade", ""),
                           ("new_violations", "new violation", ""), ("changes", "change", ""),
                           ("transient", "transient item", ""), ("problems", "problem", ""),
                           ("resolved_vulns", "resolved vulnerability", "resolved vulnerabilities")):
        if c[key]:
            bits.append(plural(c[key], one, many))
    return ", ".join(bits) if bits else "Nothing changed."


def _intro(d: dict) -> tuple[str, list[str]]:
    sysd = d.get("system") or {}
    host = sysd.get("hostname") or "?"
    status = {"alert": "ALERT", "changed": "changed", "unchanged": "unchanged"}[d["status"]]
    lines = [
        f"{span(d['start'], d['end'])} · {status} · {plural(d['reports'], 'report')}, "
        f"{plural(d['scans'], 'scan')}",
    ]
    os_line = " ".join(x for x in (sysd.get("username") and f"{sysd['username']}@{host}",
                                   sysd.get("os_name"), sysd.get("os_version"),
                                   sysd.get("architecture")) if x)
    base = "rolling baseline" if d.get("baseline") == "rolling" else f"baseline {d.get('baseline')}"
    scan = d.get("latest_scan")
    if scan:
        base += (f" · latest scan {when(scan.get('time'))}: {plural(scan.get('origins') or 0, 'origin')}, "
                 f"{plural(scan.get('sites') or 0, 'site')}, {plural(scan.get('packages') or 0, 'package')}")
    lines.append(" · ".join(x for x in (os_line, base) if x))
    return f"fetter · {host}", lines


def _footer(attached: bool, alerts_only: bool = False) -> str:
    note = (" · these are also in the next digest, marked mailed" if alerts_only else
            " · the full digest is attached as JSON" if attached else "")
    return f"fetter-scope {__version__}{note}"


#-------------------------------------------------------------------------------
# text

def text(d: dict, cap: int | None = None, attached: bool = True,
         alerts_only: bool = False) -> str:
    title, intro = _intro(d)
    out = [title, *intro, "", headline(d)]
    for s in sections(d, alerts_only):
        if s.level == 2:
            out += ["", s.title.upper(), "=" * len(s.title)]
            if not s.items:
                continue
        else:
            out += ["", s.title, "-" * len(s.title)]
        shown = s.items if cap is None else s.items[:cap]
        for it in shown:
            out.append(f"- {it.title}")
            for extra in (it.meta, it.detail, it.url):
                if extra:
                    out.append(f"  {extra}")
            if it.code:
                out += [f"    {line}" for line in it.code.splitlines()]
        if len(shown) < len(s.items):
            out.append(f"- and {len(s.items) - len(shown)} more")
    out += ["", "--", _footer(attached, alerts_only)]
    return "\n".join(out) + "\n"


#-------------------------------------------------------------------------------
# html

def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _color(tone: str) -> str:
    return C.get(tone, C["fg"]) if tone else C["fg"]


def _item_html(it: Item) -> str:
    parts = [f'<div style="font-weight:600;color:{_color(it.tone)}">{_e(it.title)}</div>']
    if it.meta:
        parts.append(f'<div style="color:{C["muted"]};font-size:12px">{_e(it.meta)}</div>')
    if it.detail:
        parts.append(f'<div style="margin-top:2px">{_e(it.detail)}</div>')
    if it.url.startswith(("https://", "http://")):
        parts.append(f'<div style="font-size:12px"><a href="{_e(it.url)}" '
                     f'style="color:{C["accent"]}">{_e(it.url)}</a></div>')
    if it.code:
        parts.append(f'<pre style="margin:4px 0 0;padding:6px 8px;background:{C["panel"]};'
                     f'border:1px solid {C["line"]};border-radius:4px;font:12px/1.4 {MONO};'
                     f'white-space:pre-wrap;word-break:break-all">{_e(it.code)}</pre>')
    return f'<div style="margin:0 0 8px">{"".join(parts)}</div>'


def html_body(d: dict, cap: int | None = None, attached: bool = True,
              alerts_only: bool = False) -> str:
    title, intro = _intro(d)
    tone = {"alert": "bad", "changed": "", "unchanged": "good"}[d["status"]]
    out = [f'<h1 style="font-size:20px;margin:0 0 4px;color:{_color(tone)}">{_e(title)}</h1>']
    for line in intro:
        out.append(f'<p style="margin:0 0 2px;color:{C["muted"]};font-size:12px">{_e(line)}</p>')
    out.append(f'<p style="margin:12px 0;font-size:15px;font-weight:600">{_e(headline(d))}</p>')
    for s in sections(d, alerts_only):
        if s.level == 2:
            out.append(f'<h2 style="font-size:16px;margin:24px 0 8px;padding-bottom:4px;'
                       f'border-bottom:1px solid {C["line"]};color:{_color(s.tone)}">{_e(s.title)}</h2>')
        else:
            out.append(f'<h3 style="font-size:12px;margin:14px 0 6px;color:{C["muted"]};'
                       f'text-transform:uppercase;letter-spacing:.04em">{_e(s.title)}</h3>')
        shown = s.items if cap is None else s.items[:cap]
        out += [_item_html(it) for it in shown]
        if len(shown) < len(s.items):
            out.append(f'<div style="color:{C["muted"]};margin:0 0 8px">and '
                       f'{len(s.items) - len(shown)} more</div>')
    out.append(f'<p style="margin:28px 0 0;color:{C["muted"]};font-size:12px">'
               f'{_e(_footer(attached, alerts_only))}</p>')
    body = "\n".join(out)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{_e(subject(d))}</title>'
            f'</head><body style="margin:0;padding:16px;background:#ffffff;color:{C["fg"]};'
            f'font:14px/1.45 {FONT}"><div style="max-width:760px;margin:0 auto">\n{body}\n'
            f'</div></body></html>\n')


def fit(d: dict, limit: int = HTML_LIMIT, attached: bool = True,
        alerts_only: bool = False) -> tuple[str, str, int | None]:
    """(html, text, cap): the largest list cap whose HTML fits under `limit` bytes."""
    for cap in CAPS:
        h = html_body(d, cap, attached, alerts_only)
        if len(h.encode()) <= limit:
            return h, text(d, cap, attached, alerts_only), cap
    return h, text(d, CAPS[-1], attached, alerts_only), CAPS[-1]
