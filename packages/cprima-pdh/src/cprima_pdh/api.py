"""Using pdh from Python: open a vault in memory, read and write secrets without a file, an argument or the command line.

This is the library surface for scripts and test automation; the rest of the package is internal and may change. pdh is a
hobby project at version 0.x: this surface can change too, and no stability is promised.

What it does about secrets, and what it does not:

- A secret comes back as a `pydantic.SecretStr`: it shows as `**********` in `print`, a log line and a traceback, and
  `.get_secret_value()` is the one explicit step that hands out the text. That guards against an accidental leak into a CI log;
  it does not stop code that wants the value.
- A vault opens read-only. Writing needs `write=True`, so a run that only reads cannot change the file.
- There is no call that returns all secrets. An account (`Account`) carries structure only; a secret is read one at a time, by
  name, and only a field that is a secret under the data boundary.
- Writes go through the same verified path as the command line: a temporary file, a check, then a replace, and a refusal while
  another program has the vault open.
- The passphrase never appears in an error message.
- Python cannot wipe memory. While a handle is open it holds every decrypted entry; `close()` drops it and the handle is
  unusable afterwards. One handle is for one thread.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from pydantic import SecretStr

from . import backends, boundary, profiles, secret_fields, spreadsheet, transfer
from . import otp as otp_mod
from cprima_pdh_kdbxkit.kdbx_format import STANDARD_PROTECTED
from cprima_pdh_kdbxkit.kdbx_vault import KdbxVault
from .credentials import Credentials, from_environment
from .credentials import secret as as_secret
from .generate import PasswordSettings
from .models import ImportReport, OtpCode
from .policy import KDBX_POLICY
from .schema import SchemaSet
from cprima_pdh_vault.vault import EntryData
from .write import WriteError, find_data

__all__ = ["Account", "FillResult", "NoSuchAccount", "OpenError", "ReadOnly", "SecretNotSet", "Vault", "VaultError", "open_vault"]


class VaultError(Exception):
    """Base of the errors of this module. None of them carries a secret."""


class OpenError(VaultError):
    """The vault could not be opened: wrong credentials, a damaged file, or a kind of vault the library does not open."""


class ReadOnly(VaultError):
    """A change was asked of a vault that was opened without `write=True`."""


class NoSuchAccount(VaultError, LookupError):
    """No account at that path, or several."""


class SecretNotSet(VaultError, LookupError):
    """The secret field exists in the taxonomy but has no value yet: fill it first."""


@dataclass(frozen=True)
class Account:
    """One entry, as structure: no secret value is in it, and a custom field that is a secret is left out."""

    id: str
    path: str  # group/title, as every command prints it
    group: str
    title: str
    username: str
    url: str
    tags: tuple[str, ...]
    fields: Mapping[str, str]  # the custom fields that are not secrets
    secrets_missing: tuple[str, ...]  # names of the secret fields that are still empty, in the taxonomy's order


@dataclass(frozen=True)
class FillResult:
    entries: int  # entries that had a secret field missing
    filled: int  # secret fields generated and stored
    still_missing: tuple[tuple[str, str], ...]  # (account path, field) that cannot be generated and are still empty


class Vault:
    """An open vault. Make one with `open_vault`; use it as a context manager so it is closed."""

    def __init__(self, path: Path, credentials: Credentials, write: bool, sset: SchemaSet):
        self._path, self._credentials, self._write, self._sset = path, credentials, write, sset
        self._vault: KdbxVault | None = self._open()

    def __repr__(self) -> str:  # nothing of the credentials, nothing of the contents
        return f"<Vault {self._path.name!r} {'read-write' if self._write else 'read-only'}{'' if self._vault else ', closed'}>"

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def close(self) -> None:
        """Drop the decrypted contents and the credentials. The handle cannot be used afterwards."""
        self._vault = None
        self._credentials = Credentials()

    # --- internals ---------------------------------------------------------------------------------------------------------

    def _open(self) -> KdbxVault:
        password = self._credentials.password
        try:
            kind = backends.select(self._path).name
        except backends.BackendMissing as exc:
            raise OpenError(str(exc)) from None
        if kind != "kdbx":
            raise OpenError(f"the library opens KDBX vaults; a {kind} file is read by the command line")
        try:
            return KdbxVault.open(self._path, password.get_secret_value() if password else None,
                                  str(self._credentials.keyfile) if self._credentials.keyfile else None, KDBX_POLICY)
        except Exception:  # noqa: BLE001 - whatever the store says, the caller gets one message that cannot carry a secret
            raise OpenError(f"cannot open {self._path.name}: wrong credentials, a damaged file or an unsupported format") from None

    def _live(self) -> KdbxVault:
        if self._vault is None:
            raise VaultError("the vault is closed")
        return self._vault

    def _need_write(self) -> None:
        self._live()
        if not self._write:
            raise ReadOnly("the vault was opened read-only; open it with write=True to change it")

    def _entry(self, account: Account | str, username: str | None = None) -> EntryData:
        vault = self._live()
        if isinstance(account, Account):
            found = next((e for e in vault.entries() if e.id == account.id), None)
            if found is None:
                raise NoSuchAccount(f"{account.path!r} is no longer in the vault")
            return found
        try:
            return find_data(vault, account, username)
        except WriteError as exc:
            raise NoSuchAccount(str(exc)) from None

    def _account(self, e: EntryData) -> Account:
        plain = {k: f.value for k, f in e.fields.items() if not f.protected and not boundary.secret_columns([k], self._sset)}
        return Account(id=e.id, path=e.path, group=e.group_path, title=e.title, username=e.username, url=e.url,
                       tags=tuple(e.tags), fields=plain,
                       secrets_missing=tuple(f.name for f in secret_fields.missing(e, self._sset)))

    def _after_write(self) -> None:
        self._vault = self._open()  # what the verified write left on disk

    # --- reading -----------------------------------------------------------------------------------------------------------

    def accounts(self, group: str | None = None, tag: str | None = None) -> list[Account]:
        """The live accounts (not the recycle bin), optionally those in `group` or below it, optionally with a tag."""
        wanted = None if group is None else ("/" if group in ("", "/") else group.strip("/"))
        out = []
        for e in self._live().entries():
            if e.in_bin:
                continue
            if wanted not in (None, "/") and e.group_path != wanted and not e.group_path.startswith(wanted + "/"):
                continue
            if tag is not None and tag not in e.tags:
                continue
            out.append(self._account(e))
        return sorted(out, key=lambda a: a.path)

    def account(self, path: str, username: str | None = None) -> Account:
        """The account at `group/title`; `username` picks among accounts that share the path."""
        return self._account(self._entry(path, username))

    def secret(self, account: Account | str, field: str = "Password") -> SecretStr:
        """One secret of one account. Only a field that is a secret is handed out; anything else is in the account itself."""
        e = self._entry(account)
        is_secret = field in STANDARD_PROTECTED or boundary.secret_columns([field], self._sset) or (
            field in e.fields and e.fields[field].protected)
        if not is_secret:
            raise ValueError(f"{field} is not a secret field; read it from the account")
        value = e.value(field) if field in ("Title", "UserName", "Password", "URL", "Notes", "otp") else (
            e.fields[field].value if field in e.fields else "")
        if not value:
            raise SecretNotSet(f"{field} of {e.path!r} has no value yet; fill it first")
        return SecretStr(value)

    def otp_code(self, account: Account | str) -> OtpCode:
        """The current one-time password of an account: the code and its seconds left, never the seed."""
        e = self._entry(account)
        try:
            params = otp_mod.params_of(e)
        except ValueError as exc:
            raise SecretNotSet(f"{e.path!r}: {exc}") from None
        if params is None:
            raise SecretNotSet(f"{e.path!r} has no one-time password")
        return otp_mod.code(params)

    # --- writing -----------------------------------------------------------------------------------------------------------

    def add_accounts(self, rows: Iterable[Mapping[str, str]], group: str = "Imported") -> ImportReport:
        """Add accounts from rows of plain data, the columns an import file has (Group, Title, UserName, URL, Notes, Tags,
        Expires, any other as a custom field). A row with a secret column is refused as a file would be: secrets are set with
        `fill` or `set_secret`."""
        self._need_write()
        data = [dict(r) for r in rows]
        header = list(dict.fromkeys(k for r in data for k in r))
        table = spreadsheet.Table(header, [{h: r.get(h, "") for h in header} for r in data], "rows")
        try:
            report = transfer.import_table(self._reopen, self._path, table, "rows given in code", group, True, self._sset)
        except WriteError as exc:
            raise VaultError(str(exc)) from None
        self._after_write()
        return report

    def fill(self, path: str, generate: PasswordSettings | None = None) -> FillResult:
        """Generate and store the secret fields that the account at `path` (or every account below that group) still lacks,
        for the fields the taxonomy allows to be generated. Nothing is returned that is a secret: read them with `secret`."""
        self._need_write()
        settings = generate or PasswordSettings()
        try:
            targets = secret_fields.fill_targets(self._live(), path, self._sset)
        except WriteError as exc:
            raise NoSuchAccount(str(exc)) from None
        pairs = [(t, f) for t in targets for f in t.fields]
        values, items = secret_fields.collect(pairs, True, settings, None)  # nobody to ask: what cannot be generated is left
        left = [(i.entry, i.field) for i in items if i.how == "skipped"]
        if values:
            try:
                secret_fields.fill_entries(self._reopen, self._path, values, True, self._sset)
            except WriteError as exc:
                raise VaultError(str(exc)) from None
            self._after_write()
        return FillResult(entries=len(targets), filled=sum(len(v) for v in values.values()), still_missing=tuple(left))

    def set_secret(self, account: Account | str, field: str, value: str | SecretStr) -> None:
        """Store one secret on an account, for a field that is a secret under the data boundary: the account's secret fields
        by its record type, or a one-time-password seed, a recovery code, a passkey key. The old value stays in the history."""
        self._need_write()
        e = self._entry(account)
        plain = value.get_secret_value() if isinstance(value, SecretStr) else value
        try:
            secret_fields.fill_entries(self._reopen, self._path, {e.id: {field: plain}}, True, self._sset, any_secret=True)
        except WriteError as exc:
            raise VaultError(str(exc)) from None
        self._after_write()

    def set_secrets(self, values: Mapping[str, Mapping[str, str | SecretStr]]) -> None:
        """Store secrets on several accounts in one verified write: `{account path: {field: value}}`. Each field follows the
        rule of `set_secret`. All or nothing: one refused field and the vault is left as it was. Use this for many accounts; one
        write per secret is slow."""
        self._need_write()
        by_id: dict[str, dict[str, str]] = {}
        for path, fields in values.items():
            e = self._entry(path)
            by_id[e.id] = {name: (v.get_secret_value() if isinstance(v, SecretStr) else v) for name, v in fields.items()}
        try:
            secret_fields.fill_entries(self._reopen, self._path, by_id, True, self._sset, any_secret=True)
        except WriteError as exc:
            raise VaultError(str(exc)) from None
        self._after_write()

    def _reopen(self) -> KdbxVault:
        return self._open()


def open_vault(path: str | Path, *, password: str | SecretStr | None = None, keyfile: str | Path | None = None,
               credentials: Credentials | None = None, write: bool = False, profile: str | SchemaSet = profiles.DEFAULT) -> Vault:
    """Open a KDBX vault. The credentials are, in this order: `credentials`, else `password` and `keyfile`, else the
    environment (KDBX_PASSWORD, KDBX_KEY). The vault is read-only unless `write=True`. `profile` names the taxonomy that decides
    which fields are secret (the default profile unless you pass another name or a loaded taxonomy)."""
    if credentials is None:
        credentials = (Credentials(as_secret(password), Path(keyfile) if keyfile else None)
                       if password is not None or keyfile is not None else from_environment())
    sset = profile if isinstance(profile, SchemaSet) else profiles.load(profile)
    return Vault(Path(path), credentials, write, sset)
