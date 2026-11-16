import stat
import textwrap
from pathlib import Path

import pytest

from fetter_scope.home import Home


@pytest.fixture
def home(tmp_path: Path) -> Home:
    return Home(tmp_path / "home")


def fake_fetter(path: Path, version: str = "5.1.0") -> Path:
    """An executable that answers `--version` like fetter."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        if [ "$1" = "--version" ]; then echo "fetter {version}"; exit 0; fi
        exit 1
        """))
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path
