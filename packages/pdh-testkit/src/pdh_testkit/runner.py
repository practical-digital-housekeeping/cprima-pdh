"""Run the `pdh` CLI in-process on stub entries: no vault file is opened, no key derivation runs."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .stubs import StubKP


def pdh_runner(monkeypatch, tmp_path: Path, toml: str | None = None) -> Callable:
    """`go(entries, *command, with_db=True)` -> click Result. Global options go before the command, as in real use."""
    from typer.testing import CliRunner

    from cprima_pdh.cli import _common, app

    db = tmp_path / "db.kdbx"
    db.write_bytes(b"")  # only has to exist: --db is checked for existence, never opened
    schemas = None
    if toml is not None:
        schemas = tmp_path / "schemas.toml"
        schemas.write_text(toml, encoding="utf-8")

    def go(entries, *command: str, with_db: bool = True):
        monkeypatch.setattr(_common, "open_db", lambda _db, _key: StubKP(entries))
        argv: list[str] = ["--db", str(db)] if with_db else []
        if schemas is not None:
            argv += ["--schemas", str(schemas)]
        return CliRunner().invoke(app, [*argv, *command])

    return go
