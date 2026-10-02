"""Genuine vaults: created and read back by KeePassXC's own keepassxc-cli. End-to-end tests only.

keepassxc-cli 2.7 creates KDBX 3.1 and cannot write custom fields; KDBX 4 vaults and vaults with custom fields
come from the KeePassXC desktop app or KeePassDX as committed fixture files.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .vault import DEFAULT_PASSWORD

ENV_VAR = "PDH_KEEPASSXC_CLI"
_WINDOWS_DEFAULT = Path(r"C:\Program Files\KeePassXC\keepassxc-cli.exe")


class KeePassXCMissing(RuntimeError):
    pass


def find_keepassxc_cli() -> Path:
    """keepassxc-cli from $PDH_KEEPASSXC_CLI, the PATH, or the default Windows install location."""
    for candidate in (os.environ.get(ENV_VAR), shutil.which("keepassxc-cli")):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    if _WINDOWS_DEFAULT.is_file():
        return _WINDOWS_DEFAULT
    raise KeePassXCMissing(f"keepassxc-cli not found; install KeePassXC or set {ENV_VAR}")


class KeePassXC:
    """A thin wrapper over keepassxc-cli. Passwords go through stdin, never through the command line."""

    def __init__(self, cli: Path | None = None) -> None:
        self.cli = cli or find_keepassxc_cli()

    def _run(self, args: list[str], stdin: str) -> str:
        done = subprocess.run([str(self.cli), *args], input=stdin, capture_output=True, text=True,
                              encoding="utf-8", timeout=120)
        if done.returncode != 0:
            raise RuntimeError(f"keepassxc-cli {args[0]} failed ({done.returncode}): {done.stderr.strip()}")
        return done.stdout

    def version(self) -> str:
        return self._run(["--version"], "").strip()

    def create(self, db: Path, password: str = DEFAULT_PASSWORD, decryption_time_ms: int | None = 100) -> Path:
        """`db-create`; `decryption_time_ms` is KeePassXC's own option for the key-derivation cost."""
        args = ["db-create", "-q", "-p"]
        if decryption_time_ms is not None:
            args += ["--decryption-time", str(decryption_time_ms)]
        self._run([*args, str(db)], f"{password}\n{password}\n")
        return db

    def mkdir(self, db: Path, group: str, password: str = DEFAULT_PASSWORD) -> None:
        self._run(["mkdir", "-q", str(db), group], f"{password}\n")

    def add(self, db: Path, entry: str, username: str = "", url: str = "", notes: str = "",
            entry_password: str | None = None, password: str = DEFAULT_PASSWORD) -> None:
        """`add` an entry at `entry` ("Group/Title"); standard fields only."""
        args = ["add", "-q"]
        if username:
            args += ["-u", username]
        if url:
            args += ["--url", url]
        if notes:
            args += ["--notes", notes]
        stdin = f"{password}\n"
        if entry_password is not None:
            args.append("-p")
            stdin += f"{entry_password}\n"
        self._run([*args, str(db), entry], stdin)

    def show(self, db: Path, entry: str, attributes: tuple[str, ...] = ("Title", "UserName", "URL"),
             password: str = DEFAULT_PASSWORD) -> dict[str, str]:
        """Read attributes back with keepassxc-cli (protected values are only shown with `-s`; not used here)."""
        args = ["show", "-q"]
        for a in attributes:
            args += ["-a", a]
        lines = self._run([*args, str(db), entry], f"{password}\n").splitlines()
        return dict(zip(attributes, lines))

    def export_xml(self, db: Path, password: str = DEFAULT_PASSWORD) -> str:
        """The decrypted KDBX XML as KeePassXC sees it (contains secrets: keep in memory only)."""
        return self._run(["export", "-q", "-f", "xml", str(db)], f"{password}\n")
