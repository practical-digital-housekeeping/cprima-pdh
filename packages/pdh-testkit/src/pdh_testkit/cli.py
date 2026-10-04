"""Run the `pdh` CLI in-process on a vault file."""
from __future__ import annotations

from pathlib import Path


def invoke(db: Path, *args: str, env: dict[str, str] | None = None):
    """`pdh --db <db> <args>` as the click Result; global options before the command, as in real use."""
    from typer.testing import CliRunner

    from cprima_pdh.cli import app

    return CliRunner().invoke(app, ["--db", str(db), *args], env=env)
