"""fetter-scope CLI.

    fetter-scope [tui]                 the terminal app (default)
    fetter-scope run [--headless]      supervisor, store and mail without the TUI
    fetter-scope attach FILE           follow a stream fetter writes itself
    fetter-scope digest [--send|--preview]
    fetter-scope check                 validate configuration, fetter and mail; print what would run
    fetter-scope install-fetter        install fetter-scope's own fetter binary
"""
import argparse
import asyncio
import json
import os
import shlex
import sys
import tempfile
import webbrowser
from pathlib import Path

from fetter_scope import __version__
from fetter_scope import config as config_mod
from fetter_scope import delivery, fetter_bin, render
from fetter_scope.digest import last_digest_end
from fetter_scope.scheduler import Mailer
from fetter_scope.home import Home
from fetter_scope.store import Store
from fetter_scope.supervisor import Headless, follow, print_followed


def _not_yet(milestone: int):
    def run(args: argparse.Namespace) -> int:
        print(f"fetter-scope {args.command}: not yet implemented (milestone {milestone})",
              file=sys.stderr)
        return 2
    return run


def cmd_check(args: argparse.Namespace) -> int:
    home = Home.locate(args.home)
    cfg = config_mod.load(home, args.config)
    ok = True

    print(f"home:    {home.root}" + ("" if home.root.is_dir() else " (not created yet)"))
    print(f"config:  {cfg.path}" + ("" if cfg.found else " (not found; using defaults)"))
    for e in cfg.errors:
        print(f"  error: {e}")
    ok &= not cfg.errors

    resolved = fetter_bin.resolve(cfg.fetter, home)
    p = fetter_bin.probe(resolved.path)
    origin = "[fetter] binary" if resolved.configured else "fetter-scope's own"
    if p.ok:
        print(f"fetter:  {p.path} ({origin}), version {p.version_str}")
        if not resolved.configured and p.version_str != fetter_bin.FETTER_VERSION:
            print(f"  note: fetter-scope pins {fetter_bin.FETTER_VERSION}; "
                  "`fetter-scope install-fetter --force` installs it")
    else:
        print(f"fetter:  {p.error} ({origin})")
        print(f"  {fetter_bin.install_hint(resolved)}")
        ok = False

    m = cfg.mail
    if not m.enabled:
        print("mail:    disabled")
    else:
        to = ", ".join(cfg.credentials.email_to) or "(none)"
        print(f"mail:    {m.transport} to {to}")
        if missing := cfg.mail_missing:
            print(f"  mail not configured: {', '.join(missing)} not set "
                  f"(in {cfg.path.parent / '.env'} or the environment)")
            ok = False
        elif args.offline:
            print("  credentials not checked (--offline)")
        else:
            v = delivery.verify(m.transport, cfg.credentials)
            print(f"  credentials {'accepted' if v.ok else 'rejected: ' + v.error} (nothing sent)")
            ok &= v.ok

    print("would run:")
    print("  " + shlex.join(fetter_bin.monitor_diff_command(resolved.path, cfg.fetter)))
    return 0 if ok else 1


def _load_runnable(args: argparse.Namespace):
    """Config and a usable fetter binary, or None after printing why not."""
    home = Home.locate(args.home)
    cfg = config_mod.load(home, args.config)
    if cfg.errors:
        print(f"fetter-scope: {cfg.path} has errors (see `fetter-scope check`):", file=sys.stderr)
        for e in cfg.errors:
            print(f"  {e}", file=sys.stderr)
        return None
    resolved = fetter_bin.resolve(cfg.fetter, home)
    p = fetter_bin.probe(resolved.path)
    if not p.ok:
        print(f"fetter-scope: {p.error}; {fetter_bin.install_hint(resolved)}", file=sys.stderr)
        return None
    return cfg, resolved


def cmd_run(args: argparse.Namespace) -> int:
    if not args.headless:
        return _not_yet(5)(args)
    loaded = _load_runnable(args)
    if loaded is None:
        return 1
    cfg, resolved = loaded
    cfg.home.ensure()
    store = Store(cfg.home)
    headless = Headless(fetter_bin.monitor_diff_command(resolved.path, cfg.fetter),
                        store, out=lambda s: print(s, flush=True),
                        retention_days=cfg.store.retention_days, mailer=Mailer(cfg, store))
    return asyncio.run(headless.run())


def cmd_attach(args: argparse.Namespace) -> int:
    """Until the TUI (milestone 5), print one line per event."""
    path = Path(args.file).expanduser()
    if not path.exists():
        print(f"fetter-scope attach: {path}: not found", file=sys.stderr)
        return 1
    try:
        asyncio.run(follow(path, print_followed(lambda s: print(s, flush=True))))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    home = Home.locate(args.home)
    cfg = config_mod.load(home, args.config)
    for e in cfg.errors:
        print(f"warning: {e}", file=sys.stderr)
    store = Store(home)
    mailer = Mailer(cfg, store)
    since = last_digest_end(store.read_state())
    if not any(p.event is not None for p in store.iter_entries(since=since)):
        print(f"nothing recorded in {home.events} since the last digest")
        return 0
    if args.send:
        if missing := cfg.mail_missing:
            print(f"fetter-scope digest: mail not configured: {', '.join(missing)} not set "
                  f"(in {cfg.path.parent / '.env'} or the environment)", file=sys.stderr)
            return 1
        result = asyncio.run(mailer.send_digest(force=True))
        if not result.ok:
            print(f"fetter-scope digest: {result.status}: {result.error}", file=sys.stderr)
            return 1
        print(f"sent to {', '.join(cfg.credentials.email_to)}")
        return 0
    d = mailer.pending()
    if args.json:
        print(json.dumps(d, indent=2, ensure_ascii=False))
        return 0
    html_body, text_body, _ = render.fit(d, attached=False)
    if args.html:
        fd, path = tempfile.mkstemp(prefix="fetter-scope-digest-", suffix=".html")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(html_body)
        print(path)
        webbrowser.open(Path(path).as_uri())
        return 0
    print(f"Subject: {render.subject(d, cfg.mail.subject_prefix)}\n")
    print(text_body, end="")
    return 0


def cmd_install_fetter(args: argparse.Namespace) -> int:
    home = Home.locate(args.home)
    try:
        print(fetter_bin.install(home, method=args.method, force=args.force))
    except fetter_bin.InstallError as e:
        print(f"fetter-scope install-fetter: {e}", file=sys.stderr)
        return 1
    cfg = config_mod.load(home, args.config)
    if cfg.fetter.binary:
        print(f"note: [fetter] binary = {cfg.fetter.binary!r} in {cfg.path} overrides it")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", metavar="DIR", default=argparse.SUPPRESS,
                        help="fetter-scope's directory (default: $FETTER_SCOPE_HOME or ~/.fetter-scope)")
    common.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS,
                        help="config.toml to read (default: in the home directory)")

    parser = argparse.ArgumentParser(prog="fetter-scope", parents=[common],
                                     description="Show and mail what fetter monitor-diff finds changing.")
    parser.add_argument("--version", action="version", version=f"fetter-scope {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("tui", parents=[common], help="the terminal app (default)")
    p.set_defaults(func=_not_yet(5))
    p = sub.add_parser("run", parents=[common], help="run fetter and the event log (and mail)")
    p.add_argument("--headless", action="store_true",
                   help="without the TUI, printing one line per event (for a service)")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("attach", parents=[common],
                       help="follow a stream fetter writes itself (`monitor-diff json -o FILE`), "
                            "or fetter-scope's events/ directory")
    p.add_argument("file")
    p.set_defaults(func=cmd_attach)
    p = sub.add_parser("digest", parents=[common],
                       help="preview (the default) or send the digest of everything since the last one")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--send", action="store_true", help="send it now")
    g.add_argument("--preview", action="store_true", help="print its subject and text body")
    g.add_argument("--html", action="store_true", help="write its HTML to a temp file and open it")
    g.add_argument("--json", action="store_true", help="print the folded digest")
    p.set_defaults(func=cmd_digest)
    p = sub.add_parser("check", parents=[common],
                       help="validate configuration, fetter and mail; print what would run")
    p.add_argument("--offline", action="store_true",
                   help="do not contact the mail service to check credentials")
    p.set_defaults(func=cmd_check)
    p = sub.add_parser("install-fetter", parents=[common],
                       help=f"install fetter {fetter_bin.FETTER_VERSION} into the home directory")
    p.add_argument("--method", choices=("auto", "cargo", "pypi"), default="auto",
                   help="auto: cargo when on PATH, else the PyPI wheel")
    p.add_argument("--force", action="store_true", help="reinstall even if already installed")
    p.set_defaults(func=cmd_install_fetter)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.home = getattr(args, "home", None)
    args.config = getattr(args, "config", None)
    if args.command is None:
        args.command = "tui"
        args.func = _not_yet(5)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
