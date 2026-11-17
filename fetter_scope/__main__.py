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
import time
import webbrowser
from pathlib import Path

from fetter_scope import __version__
from fetter_scope import config as config_mod
from fetter_scope import delivery, fetter_bin, render
from fetter_scope.digest import last_digest_end
from fetter_scope.scheduler import Mailer
from fetter_scope.sites import Inventory, open_inventory
from fetter_scope.home import Home
from fetter_scope.store import Store
from fetter_scope.supervisor import Runtime, follow, print_followed


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
        sources = [str(f) for f in config_mod.env_files(cfg.path, os.environ)] + ["the environment"]
        print(f"  credentials from: {', '.join(sources)}")
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
    return cfg, resolved, p


def cmd_tui(args: argparse.Namespace) -> int:
    """The TUI, running fetter: the pending period is replayed from events/ first."""
    loaded = _load_runnable(args)
    if loaded is None:
        return 1
    cfg, resolved, probe = loaded
    from fetter_scope.model import Model
    from fetter_scope.tui import ScopeApp
    cfg.home.ensure()
    store = Store(cfg.home)
    mailer = Mailer(cfg, store)
    model = Model(feed_limit=cfg.tui.feed_limit, inventory=open_inventory(store))
    since = last_digest_end(store.read_state())
    for p in store.iter_entries(since=since if since is not None else time.time() - 86400):
        model.add(p)
    model.fetter = "not running"           # until this run's launch
    runtime = Runtime(fetter_bin.monitor_diff_command(resolved.path, cfg.fetter), store,
                      out=None, retention_days=cfg.store.retention_days, mailer=mailer,
                      signals=False, inventory=model.inventory)
    app = ScopeApp(model, runtime=runtime, store=store, mailer=mailer, period=cfg.fetter.period,
                   baseline=cfg.fetter.baseline or "rolling", fetter_version=probe.version_str,
                   theme=cfg.tui.theme,
                   load_config=lambda: config_mod.load(cfg.home, args.config))
    runtime.tap = app.ingest
    app.run()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not args.headless:
        return cmd_tui(args)
    loaded = _load_runnable(args)
    if loaded is None:
        return 1
    cfg, resolved, _ = loaded
    cfg.home.ensure()
    store = Store(cfg.home)
    headless = Runtime(fetter_bin.monitor_diff_command(resolved.path, cfg.fetter),
                        store, out=lambda s: print(s, flush=True),
                        retention_days=cfg.store.retention_days, mailer=Mailer(cfg, store),
                        inventory=open_inventory(store))
    return asyncio.run(headless.run())


def cmd_attach(args: argparse.Namespace) -> int:
    """Follow a stream read-only: the TUI, or with --print one line per entry."""
    path = Path(args.file).expanduser()
    if not path.exists():
        print(f"fetter-scope attach: {path}: not found", file=sys.stderr)
        return 1
    if args.print:
        try:
            asyncio.run(follow(path, print_followed(lambda s: print(s, flush=True))))
        except KeyboardInterrupt:
            pass
        return 0
    from fetter_scope.model import Model
    from fetter_scope.tui import ScopeApp
    home = Home.locate(args.home)
    cfg = config_mod.load(home, args.config)
    # fetter-scope's own events/ directory: its home's state gives the digest period
    store = Store(Home(path.parent)) if path.is_dir() and path.name == "events" else None
    # with a home, its saved inventory; the followed stream tops it up (earlier reports are skipped)
    model = Model(feed_limit=cfg.tui.feed_limit, attached=True,
                  inventory=open_inventory(store) if store is not None else Inventory())
    ScopeApp(model, follow_path=path, store=store, period=cfg.fetter.period,
             baseline=cfg.fetter.baseline or "rolling", theme=cfg.tui.theme).run()
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

    p = sub.add_parser("tui", parents=[common], help="the terminal app, running fetter (default)")
    p.set_defaults(func=cmd_tui)
    p = sub.add_parser("run", parents=[common], help="run fetter and the event log (and mail)")
    p.add_argument("--headless", action="store_true",
                   help="without the TUI, printing one line per event (for a service)")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("attach", parents=[common],
                       help="follow a stream fetter writes itself (`monitor-diff json -o FILE`), "
                            "or fetter-scope's events/ directory")
    p.add_argument("file")
    p.add_argument("--print", action="store_true", help="print one line per entry, without the TUI")
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
        args.func = cmd_tui
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
