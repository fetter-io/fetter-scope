"""The fetter-scope home directory: configuration, credentials, fetter's binary, and data.

One directory on every platform, `~/.fetter-scope/` (Windows: `%USERPROFILE%\\.fetter-scope\\`),
since fetter-scope may be installed in a user's site-packages and keeps nothing beside the
package. `--home DIR` or `$FETTER_SCOPE_HOME` overrides it.
"""
import os
import sys
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "FETTER_SCOPE_HOME"
DIR_NAME = ".fetter-scope"


@dataclass(frozen=True)
class Home:
    root: Path

    @classmethod
    def locate(cls, home: str | os.PathLike | None = None) -> "Home":
        """`home` (from `--home`), else `$FETTER_SCOPE_HOME`, else `~/.fetter-scope`."""
        if home is None:
            home = os.environ.get(ENV_HOME) or None
        root = Path(home).expanduser() if home is not None else Path.home() / DIR_NAME
        return cls(root.absolute())

    @property
    def config(self) -> Path:
        return self.root / "config.toml"

    @property
    def env(self) -> Path:
        return self.root / ".env"

    @property
    def bin_dir(self) -> Path:
        return self.root / "bin"

    @property
    def fetter(self) -> Path:
        return self.bin_dir / ("fetter.exe" if sys.platform == "win32" else "fetter")

    @property
    def events(self) -> Path:
        return self.root / "events"

    @property
    def mail(self) -> Path:
        return self.root / "mail"

    @property
    def state(self) -> Path:
        return self.root / "state.json"

    def ensure(self) -> Path:
        """Create the root (mode 0700: events hold user names and local paths). Not used by `check`."""
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        return self.root
