"""Passwords and passphrases from the operating system's secure random source (`secrets`). Printed, never stored."""
from __future__ import annotations

import math
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
MIN_LENGTH, MIN_WORDS, MIN_LIST = 8, 4, 1024


def password(length: int, symbols: bool = True) -> str:
    """A random password with at least one lower case letter, upper case letter, digit and (if asked) symbol."""
    if length < MIN_LENGTH:
        raise ValueError(f"a password needs at least {MIN_LENGTH} characters")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits, *([SYMBOLS] if symbols else [])]
    chars = [secrets.choice(c) for c in classes]  # one of every class ...
    pool = "".join(classes)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]  # ... the rest from all of them
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def password_entropy(length: int, symbols: bool = True) -> float:
    """Entropy of the unconstrained draw over the whole alphabet (the class guarantee costs a little)."""
    return length * math.log2(len(string.ascii_letters + string.digits) + (len(SYMBOLS) if symbols else 0))


def passphrase(words: list[str], count: int, separator: str) -> str:
    """`count` words drawn at random from `words`, joined by `separator`."""
    if count < MIN_WORDS:
        raise ValueError(f"a passphrase needs at least {MIN_WORDS} words")
    if len(set(words)) < MIN_LIST:
        raise ValueError(f"the word list needs at least {MIN_LIST} different words")
    unique = sorted(set(words))
    return separator.join(secrets.choice(unique) for _ in range(count))


def passphrase_entropy(list_size: int, count: int) -> float:
    return count * math.log2(list_size)
