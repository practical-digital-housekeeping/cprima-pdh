"""Small tools that need no vault: the password generator."""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import generate as generate_mod
from ..models import Generated
from ..render import Format
from . import _common as c


def generate(
    fmt: c.Fmt = Format.text,
    length: Annotated[int, typer.Option("--length", help="Characters of a password.")] = 20,
    symbols: Annotated[bool, typer.Option("--symbols/--no-symbols", help="Include symbols in a password.")] = True,
    passphrase: Annotated[bool, typer.Option("--passphrase", help="Words instead of characters (needs --words).")] = False,
    words: Annotated[Optional[Path], typer.Option("--words", help="Word list for a passphrase, one word per line.")] = None,
    count: Annotated[int, typer.Option("--count", help="Words of a passphrase.")] = 6,
    separator: Annotated[str, typer.Option("--separator", help="Between the words of a passphrase.")] = "-",
) -> None:
    """Generate a password or passphrase and print it (never stored). Uses the system's secure random source."""
    try:
        if passphrase:
            if words is None:
                c.fail("a passphrase needs a word list: --words FILE (for example one of the EFF lists)")
            try:
                lines = [w.strip() for w in words.read_text(encoding="utf-8").splitlines() if w.strip()]
            except OSError as exc:
                c.fail(f"cannot read {words}: {exc.strerror or exc}")
            result = Generated(kind="passphrase", value=generate_mod.passphrase(lines, count, separator),
                               entropy_bits=round(generate_mod.passphrase_entropy(len(set(lines)), count), 2))
        else:
            result = Generated(kind="password", value=generate_mod.password(length, symbols),
                               entropy_bits=round(generate_mod.password_entropy(length, symbols), 2))
    except ValueError as exc:
        c.fail(str(exc))
    c.emit(result, fmt)
