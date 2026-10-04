"""Passwords and passphrases from the operating system's secure random source (`secrets`).

The knobs are those of KeePassXC and KeePassDX, so what a person knows from those clients works here: a length, the groups of
characters to draw from, characters to include or exclude, "exclude look-alikes", "a character from every group", and for a
passphrase the word count, separator and word case. The behaviour is the same; the code is our own. Settings are plain values
(`PasswordSettings`, `PassphraseSettings`) so a command line, a config file or a script can all state them the same way.
"""
from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass, replace

MIN_LENGTH, MIN_WORDS, MIN_LIST = 8, 4, 1024

# --- the groups of characters ------------------------------------------------------------------------------------------
# Named as in KeePassXC (its "advanced" groups); KeePassDX's minus and underline are inside `dashes`, its brackets are
# `braces` and the angle brackets of `math`. `space` is KeePassDX's. `extended` is the printable Latin-1 range both use.
GROUPS: dict[str, str] = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "braces": "()[]{}",
    "punctuation": ",.:;",
    "quotes": "\"'",
    "dashes": "-/\\_|",
    "math": "!*+<=>?",
    "logograms": "#$%&@^`~",
    "space": " ",
    "extended": "".join(chr(c) for c in [*range(0xA1, 0xAD), *range(0xAE, 0x100)]),  # not the soft hyphen or the no-break space
}
SPECIAL = ("braces", "punctuation", "quotes", "dashes", "math", "logograms")  # what the clients call "special characters"
DEFAULT_GROUPS = ("lower", "upper", "digits")
# What the two clients leave out when asked to exclude look-alikes, both lists together.
SIMILAR = "iIlL|oO01BG68"
DEFAULT_LENGTH = 20


@dataclass(frozen=True)
class PasswordSettings:
    length: int = DEFAULT_LENGTH
    groups: tuple[str, ...] = DEFAULT_GROUPS
    include: str = ""  # further characters to draw from, as a group of their own
    exclude: str = ""  # characters never drawn
    exclude_similar: bool = True
    every_group: bool = True  # at least one character from each group (and from `include`)

    def with_groups(self, **chosen: bool) -> PasswordSettings:
        """The settings with groups switched on or off by name; `special=True` switches on all of `SPECIAL`."""
        groups = list(self.groups)
        for name, on in chosen.items():
            names = SPECIAL if name == "special" else (name,)
            for g in names:
                if on and g not in groups:
                    groups.append(g)
                if not on and g in groups:
                    groups.remove(g)
        return replace(self, groups=tuple(g for g in GROUPS if g in groups))


@dataclass(frozen=True)
class PassphraseSettings:
    words: int = 6
    separator: str = "-"
    case: str = "lower"  # lower | upper | title


CASES = ("lower", "upper", "title")


# --- passwords -----------------------------------------------------------------------------------------------------------

def _forbidden(settings: PasswordSettings) -> set[str]:
    return set(settings.exclude) | (set(SIMILAR) if settings.exclude_similar else set())


def pools(settings: PasswordSettings) -> list[tuple[str, str]]:
    """The groups to draw from as (name, characters), after exclusions. A group that nothing is left of is an error."""
    unknown = [g for g in settings.groups if g not in GROUPS]
    if unknown:
        raise ValueError(f"unknown character group {unknown[0]!r}; known: {', '.join(GROUPS)}")
    gone = _forbidden(settings)
    out: list[tuple[str, str]] = []
    for name in settings.groups:
        chars = "".join(c for c in GROUPS[name] if c not in gone)
        if not chars:
            raise ValueError(f"the group {name!r} has no character left after the exclusions")
        out.append((name, chars))
    extra = "".join(dict.fromkeys(c for c in settings.include if c not in gone))
    if settings.include and not extra:
        raise ValueError("every character to include is also excluded")
    if extra:
        out.append(("include", extra))
    if not out:
        raise ValueError("no character group is selected")
    return out


def check(settings: PasswordSettings) -> list[tuple[str, str]]:
    """The pools for `settings`, after checking the length: at least MIN_LENGTH, and room for one from every group."""
    chosen = pools(settings)
    if settings.length < MIN_LENGTH:
        raise ValueError(f"a password needs at least {MIN_LENGTH} characters")
    if settings.every_group and settings.length < len(chosen):
        raise ValueError(f"a password with a character from each of {len(chosen)} groups needs at least that many characters")
    return chosen


def generate_password(settings: PasswordSettings | None = None) -> str:
    """A random password as `settings` say. Every character is drawn with `secrets`; with `every_group` one from each group is
    placed first and the rest drawn from all groups, then the order is shuffled."""
    settings = settings or PasswordSettings()
    chosen = check(settings)
    everything = "".join(dict.fromkeys("".join(chars for _, chars in chosen)))
    chars = [secrets.choice(chars) for _, chars in chosen] if settings.every_group else []
    chars += [secrets.choice(everything) for _ in range(settings.length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_entropy(settings: PasswordSettings | None = None) -> float:
    """Entropy of the unconstrained draw over the whole alphabet (the guarantee of one per group costs a little)."""
    settings = settings or PasswordSettings()
    alphabet = set("".join(chars for _, chars in pools(settings)))
    return settings.length * math.log2(len(alphabet))


# --- passphrases ---------------------------------------------------------------------------------------------------------

def _cased(word: str, case: str) -> str:
    if case == "upper":
        return word.upper()
    if case == "title":
        return word.title()
    return word.lower()


def generate_passphrase(words: list[str], settings: PassphraseSettings | None = None) -> str:
    """`settings.words` words drawn at random from the list, in the chosen case, joined by the separator."""
    settings = settings or PassphraseSettings()
    if settings.case not in CASES:
        raise ValueError(f"unknown word case {settings.case!r}; known: {', '.join(CASES)}")
    if settings.words < MIN_WORDS:
        raise ValueError(f"a passphrase needs at least {MIN_WORDS} words")
    unique = sorted(set(words))
    if len(unique) < MIN_LIST:
        raise ValueError(f"the word list needs at least {MIN_LIST} different words")
    return settings.separator.join(_cased(secrets.choice(unique), settings.case) for _ in range(settings.words))


def passphrase_entropy(list_size: int, count: int) -> float:
    return count * math.log2(list_size)
