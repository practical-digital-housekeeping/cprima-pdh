"""The credentials that open a vault when code, not a person, does the opening.

The master passphrase is one secret that opens a store (see the README, "Data boundary"). Code gets it from the environment,
as a CI system injects it, or is handed it; it is held as a `SecretStr`, which does not show itself in `print`, a log line or a
traceback. The command line has its own channels for a person (a hidden prompt, `--password-stdin`, the session).
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

PASSWORD_ENV = "KDBX_PASSWORD"
KEYFILE_ENV = "KDBX_KEY"


@dataclass(frozen=True)
class Credentials:
    password: SecretStr | None = None
    keyfile: Path | None = None


def secret(value: str | SecretStr | None) -> SecretStr | None:
    """`value` as a SecretStr; an empty or missing one is None."""
    if value is None or value == "":
        return None
    return value if isinstance(value, SecretStr) else SecretStr(value)


def from_environment(environ: Mapping[str, str] | None = None) -> Credentials:
    """The passphrase in KDBX_PASSWORD and the key file in KDBX_KEY, as the command line reads them. An empty variable is not set."""
    env = os.environ if environ is None else environ
    keyfile = env.get(KEYFILE_ENV, "")
    return Credentials(secret(env.get(PASSWORD_ENV, "")), Path(keyfile) if keyfile else None)
