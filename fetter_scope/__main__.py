"""fetter-scope CLI.

    fetter-scope [tui]                 the terminal app (default)
    fetter-scope run [--headless]      supervisor, store and mail without the TUI
    fetter-scope attach FILE           follow a stream fetter writes itself
    fetter-scope digest [--send|--preview]
    fetter-scope check                 validate configuration, fetter and mail; print what would run
    fetter-scope install-fetter        install fetter-scope's own fetter binary
"""
import argparse
import shlex
import sys

from fetter_scope import __version__
from fetter_scope import config as config_mod
from fetter_scope import fetter_bin
from fetter_scope.home import Home


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

    print("would run:")
    print("  " + shlex.join(fetter_bin.monitor_diff_command(resolved.path, cfg.fetter)))
    return 0 if ok else 1


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
    p = sub.add_parser("run", parents=[common], help="run without the TUI")
    p.add_argument("--headless", action="store_true")
    p.set_defaults(func=_not_yet(2))
    p = sub.add_parser("attach", parents=[common], help="follow a stream fetter writes itself")
    p.add_argument("file")
    p.set_defaults(func=_not_yet(2))
    p = sub.add_parser("digest", parents=[common], help="send or preview the pending digest")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--send", action="store_true")
    g.add_argument("--preview", action="store_true")
    p.set_defaults(func=_not_yet(3))
    p = sub.add_parser("check", parents=[common],
                       help="validate configuration, fetter and mail; print what would run")
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
