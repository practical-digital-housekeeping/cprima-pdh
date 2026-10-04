"""The generator's knobs on the command line, named as `keepassxc-cli generate` names them, shared by every command that generates."""
from __future__ import annotations

from typing import Annotated

import typer

from ..generate import DEFAULT_LENGTH, PasswordSettings

Length = Annotated[int, typer.Option("--length", "-L", help="Characters of a password.")]
Lower = Annotated[bool, typer.Option("--lower/--no-lower", "-l", help="Draw from lower case letters.")]
Upper = Annotated[bool, typer.Option("--upper/--no-upper", "-U", help="Draw from upper case letters.")]
Numeric = Annotated[bool, typer.Option("--numeric/--no-numeric", "-n", help="Draw from digits.")]
Special = Annotated[bool, typer.Option("--special/--no-special", "-s", help="Draw from special characters "
                                       "(braces, punctuation, quotes, dashes, math, logograms).")]
Extended = Annotated[bool, typer.Option("--extended/--no-extended", "-e", help="Draw from extended ASCII (Latin-1) characters.")]
Space = Annotated[bool, typer.Option("--space/--no-space", help="Draw from the space character.")]
Include = Annotated[str, typer.Option("--include", help="Further characters to draw from, as a group of their own.")]
Exclude = Annotated[str, typer.Option("--exclude", "-x", help="Characters never to draw (list them one after the other).")]
ExcludeSimilar = Annotated[bool, typer.Option("--exclude-similar/--no-exclude-similar", help="Leave out characters that look "
                                              "alike (0 O 1 l I | ...).")]
EveryGroup = Annotated[bool, typer.Option("--every-group/--no-every-group", help="Use at least one character from every group.")]

DEFAULTS = PasswordSettings()


def password_settings(length: int, lower: bool, upper: bool, numeric: bool, special: bool, extended: bool, space: bool,
                      include: str, exclude: str, exclude_similar: bool, every_group: bool) -> PasswordSettings:
    """The settings the options state."""
    base = PasswordSettings(length=length, groups=(), include=include, exclude=exclude, exclude_similar=exclude_similar,
                            every_group=every_group)
    return base.with_groups(lower=lower, upper=upper, digits=numeric, special=special, extended=extended, space=space)


__all__ = ["DEFAULTS", "DEFAULT_LENGTH", "EveryGroup", "Exclude", "ExcludeSimilar", "Extended", "Include", "Length", "Lower",
           "Numeric", "Space", "Special", "Upper", "password_settings"]
