"""Small tools that need no vault: the password generator."""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import generate as generate_mod
from ..models import Generated
from ..render import Format
from . import _common as c
from . import _generator as g

CaseOption = Annotated[str, typer.Option("--case", help="Case of the words of a passphrase: lower, upper or title.")]


def generate(
    fmt: c.Fmt = Format.text,
    length: g.Length = g.DEFAULTS.length,
    lower: g.Lower = True,
    upper: g.Upper = True,
    numeric: g.Numeric = True,
    special: g.Special = False,
    extended: g.Extended = False,
    space: g.Space = False,
    include: g.Include = "",
    exclude: g.Exclude = "",
    exclude_similar: g.ExcludeSimilar = g.DEFAULTS.exclude_similar,
    every_group: g.EveryGroup = g.DEFAULTS.every_group,
    passphrase: Annotated[bool, typer.Option("--passphrase", help="Words instead of characters (needs --words).")] = False,
    words: Annotated[Optional[Path], typer.Option("--words", help="Word list for a passphrase, one word per line.")] = None,
    count: Annotated[int, typer.Option("--count", help="Words of a passphrase.")] = 6,
    separator: Annotated[str, typer.Option("--separator", help="Between the words of a passphrase.")] = "-",
    case: CaseOption = "lower",
) -> None:
    """Generate a password or passphrase and print it (never stored). Uses the system's secure random source. The options are
    those of KeePassXC and KeePassDX: which groups of characters to draw from, which to include or exclude, whether to leave
    out look-alikes and to use every group; for a passphrase the word count, separator and case."""
    try:
        if passphrase:
            if words is None:
                c.fail("a passphrase needs a word list: --words FILE (for example one of the EFF lists)")
            try:
                lines = [w.strip() for w in words.read_text(encoding="utf-8").splitlines() if w.strip()]
            except OSError as exc:
                c.fail(f"cannot read {words}: {exc.strerror or exc}")
            settings = generate_mod.PassphraseSettings(words=count, separator=separator, case=case)
            result = Generated(kind="passphrase", value=generate_mod.generate_passphrase(lines, settings),
                               entropy_bits=round(generate_mod.passphrase_entropy(len(set(lines)), count), 2))
        else:
            chosen = g.password_settings(length, lower, upper, numeric, special, extended, space, include, exclude,
                                         exclude_similar, every_group)
            result = Generated(kind="password", value=generate_mod.generate_password(chosen),
                               entropy_bits=round(generate_mod.password_entropy(chosen), 2))
    except ValueError as exc:
        c.fail(str(exc))
    c.emit(result, fmt)
