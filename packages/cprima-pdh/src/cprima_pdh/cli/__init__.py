"""The `pdh` command: Practical Digital Housekeeping.

Global options (vault, key file, taxonomy) are given once, before the command group:
    pdh --db vault.kdbx check conform -f json
They also come from the environment: KDBX_FILE, KDBX_KEY, PDH_SCHEMAS.
"""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer

from .. import __version__, backends, profiles
from .. import config as config_mod
from .. import doctor as doctor_mod
from .. import session as session_mod
from .. import source as source_mod
from ..models import BackendList, BackendRow
from ..render import Format
from . import _common as c
from . import check, db, edit, inspect, io, method, serve, session, tools

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="Practical Digital Housekeeping. Keep it tidy. Keep it trustworthy.")
app.add_typer(session.app, name="session")
app.add_typer(inspect.app, name="inspect")
app.add_typer(check.app, name="check")
app.add_typer(edit.app, name="edit")
app.add_typer(method.app, name="method")
app.add_typer(db.app, name="db")
app.add_typer(io.app, name="io")
app.command("generate")(tools.generate)
app.command("serve")(serve.serve)


def _version(value: bool) -> None:
    if value:
        typer.echo(f"pdh {__version__} (cprima-pdh, Practical Digital Housekeeping)")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    db: Annotated[Optional[Path], typer.Option("--db", envvar="KDBX_FILE", exists=True, dir_okay=False,
                                               help="Vault file (env KDBX_FILE).")] = None,
    vault: Annotated[Optional[str], typer.Option("--vault", envvar="PDH_VAULT",
                                                 help="A vault by its name in the config (env PDH_VAULT).")] = None,
    key: Annotated[Optional[Path], typer.Option("--key", envvar="KDBX_KEY", help="Key file (env KDBX_KEY).")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile", envvar="PDH_PROFILE",
                                                   help="The taxonomy profile (env PDH_PROFILE); see "
                                                        "`pdh method profiles`.")] = None,
    schemas: Annotated[Optional[Path], typer.Option("--schemas", envvar="PDH_SCHEMAS", exists=True, dir_okay=False,
                                                    help="One taxonomy file instead of a profile (env PDH_SCHEMAS).")] = None,
    version: Annotated[Optional[bool], typer.Option("--version", callback=_version, is_eager=True,
                                                    help="Show the version.")] = None,
) -> None:
    """Practical Digital Housekeeping: keep your digital life in order, starting with your password database.

    The vault: --db, else --vault/PDH_VAULT (a name in the config), else KDBX_FILE, else the config's default,
    else the vault of the unlocked session. The profile: --profile/PDH_PROFILE, else the vault's own `profile` in the
    config, else the config's `profile`, else `pdh-default`. Config files: ~/.config/cprima-pdh/config.toml, ./pdh.toml,
    $PDH_CONFIG."""
    source = ctx.get_parameter_source("db")  # COMMANDLINE or ENVIRONMENT (KDBX_FILE)
    try:
        resolved = config_mod.resolve_vault(
            db, getattr(source, "name", "") == "ENVIRONMENT", key, vault,
            config_mod.load_config(), session_mod.current_vault())
    except config_mod.ConfigError as exc:
        c.fail(f"config error: {exc}")
    if profile is not None:
        chosen, origin = profile, ("PDH_PROFILE" if getattr(ctx.get_parameter_source("profile"), "name", "") ==
                                   "ENVIRONMENT" else "--profile")
    elif resolved.profile:
        chosen, origin = resolved.profile, resolved.profile_source
    else:
        chosen, origin = profiles.DEFAULT, ""
    ctx.obj = c.AppState(db=resolved.db, key=resolved.key, schemas=schemas, profile=chosen, profile_origin=origin,
                         vault_source=resolved.source)


@app.command()
def doctor(ctx: typer.Context, fmt: c.Fmt = Format.text) -> None:
    """Overview: pdh, backend, taxonomy, vault file, lock and sync conflicts, session, and (when unlocked) the
    vault's conformance. Read-only; never asks for the password. Exit 1 if a check fails."""
    st = c.state(ctx)

    def open_unlocked(db: Path):
        if source_mod.file_kind(db) == "sops":  # an age identity instead of a password; errors reach the report
            from ..backends import age
            from ..backends.sops import SopsVault, default_identities

            return SopsVault.open(db, age.load_identities(st.key) if st.key else default_identities())
        # only with a sidecar password or a session: doctor never prompts
        if source_mod.sidecar(db) is None and session_mod.load_session(db) is None:
            return None
        return c.open_db(db, st.key)

    report = doctor_mod.diagnose(st.db, lambda: c.read_taxonomy(st), c.taxonomy_source(st), open_unlocked,
                                 vault_source=st.vault_source, taxonomy_origin=c.taxonomy_origin(st))
    c.emit(report, fmt)
    if report.failed:
        raise typer.Exit(1)


@app.command("backends")
def list_backends(fmt: c.Fmt = Format.text) -> None:
    """List the installed backends and whether their dependencies are present."""
    c.emit(BackendList(backends=[BackendRow(name=b.name, ready=b.available, detail=b.detail)
                                 for b in backends.available()]), fmt)
