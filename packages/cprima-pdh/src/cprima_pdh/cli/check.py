"""`pdh check`: does the vault conform to the method? Read-only."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Optional

import typer

import os
from pathlib import Path

from .. import conform as conform_mod
from .. import net
from .. import online as online_mod
from .. import schema
from ..models import LEVEL_ORDER
from ..render import Format
from . import _common as c

app = typer.Typer(help="Check the vault against the taxonomy. `pdh check` alone lists the nonconforming entries.")


class StatusName(str, Enum):
    conform = "conform"
    nonconform = "nonconform"
    unclassified = "unclassified"
    all = "all"


def _run_conform(ctx: typer.Context, fmt: Format, status: StatusName, only_schema: str | None, level: c.LevelName) -> None:
    st = c.state(ctx)
    kp = c.open_vault(c.require_db(st), st.key)
    c.emit(conform_mod.conformance(kp, c.load_taxonomy(st), status.value, only_schema, level.value), fmt)


@app.callback(invoke_without_command=True)
def default(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        _run_conform(ctx, Format.text, StatusName.nonconform, None, c.LevelName.INFO)


@app.command("conform")
def conform_cmd(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    status: Annotated[StatusName, typer.Option("--status", help="Which entries to list.")] = StatusName.nonconform,
    only_schema: Annotated[Optional[str], typer.Option("--schema", help="Only entries naming this schema.")] = None,
    level: Annotated[c.LevelName, typer.Option("--level", help="Count findings at this level and above.")] = c.LevelName.INFO,
) -> None:
    """Entries that conform and entries that do not, each issue with an action (use -f json for an agent).
    Read-only: the commands it suggests are for you or an agent to run, dry run first."""
    _run_conform(ctx, fmt, status, only_schema, level)


Online = Annotated[bool, typer.Option("--online", help="Allow network access; without it nothing is looked up.")]


def _kp(ctx: typer.Context):
    st = c.state(ctx)
    return c.open_vault(c.require_db(st), st.key)


@app.command("known-passwords")
def known_passwords(
    ctx: typer.Context, fmt: c.Fmt = Format.text, online: Online = False,
    hashes: Annotated[Optional[Path], typer.Option(
        "--hashes", help="A local, sorted SHA-1 list (HASH:COUNT lines) instead of the network.")] = None,
    fail_on: Annotated[c.LevelName, typer.Option("--fail-on", help="Exit 1 if any finding is at this level or above.")]
    = c.LevelName.ERROR,
) -> None:
    """Which passwords appear in known leaks. Online, only the first 5 characters of each SHA-1 are sent
    (k-anonymity); the report names entries and counts, never a password or a hash. The level and advice of a finding
    come from the profile (`known-password`); exit 1 if one reaches --fail-on."""
    if not online and hashes is None:
        c.fail("nothing was looked up: give --online (HIBP range API) or --hashes FILE (a local list)")
    kp = _kp(ctx)
    try:
        report = online_mod.known_passwords_file(kp, hashes) if hashes is not None else online_mod.known_passwords_online(kp)
    except net.NetworkError as exc:
        c.fail(f"online check failed: {exc}")
    except OSError as exc:
        c.fail(f"cannot read {hashes}: {exc.strerror or exc}")
    report = online_mod.judge(report, c.load_taxonomy(c.state(ctx)))
    c.emit(report, fmt)
    if online_mod.worst_level(report) >= LEVEL_ORDER[fail_on.value]:
        raise typer.Exit(1)


@app.command("breaches")
def breaches(
    ctx: typer.Context, fmt: c.Fmt = Format.text, online: Online = False,
    accounts: Annotated[bool, typer.Option(
        "--accounts", help="Also ask whether each e-mail address (a user name that is one) is in a breach: this sends "
                           "the addresses to the service and needs an API key in HIBP_API_KEY.")] = False,
    fail_on: Annotated[c.LevelName, typer.Option("--fail-on", help="Exit 1 if any finding is at this level or above.")]
    = c.LevelName.ERROR,
) -> None:
    """Which of your sites were breached, and was the entry changed since? Compares the public breach catalogue with
    your URLs locally; nothing from the vault is sent (except with --accounts). The level and advice of each
    finding come from the profile (`breach:*`); exit 1 if one reaches --fail-on."""
    if not online:
        c.fail("nothing was looked up: give --online (it downloads the public breach catalogue)")
    key = os.environ.get("HIBP_API_KEY", "")
    if accounts and not key:
        c.fail("--accounts needs an API key in the environment variable HIBP_API_KEY")
    kp = _kp(ctx)
    try:
        report = online_mod.breach_report(kp, accounts, key)
    except net.NetworkError as exc:
        c.fail(f"online check failed: {exc}")
    report = online_mod.judge(report, c.load_taxonomy(c.state(ctx)))
    c.emit(report, fmt)
    if online_mod.worst_level(report) >= LEVEL_ORDER[fail_on.value]:
        raise typer.Exit(1)


@app.command()
def validate(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    summary: Annotated[bool, typer.Option("--summary", help="Counts per schema and rule, no entry list.")] = False,
    level: Annotated[c.LevelName, typer.Option("--level", help="Show findings at this level and above.")] = c.LevelName.INFO,
    fail_on: Annotated[
        c.LevelName, typer.Option("--fail-on", help="Exit 1 if any finding is at this level or above.")
    ] = c.LevelName.ERROR,
) -> None:
    """Every finding with its level (ERROR, WARN, INFO), like log levels; exit 1 only if a finding reaches
    --fail-on (default ERROR)."""
    st = c.state(ctx)
    report = schema.validate(c.open_vault(c.require_db(st), st.key), c.load_taxonomy(st))
    shown = schema.filter_level(report, level.value)
    c.emit(schema.summarize(shown) if summary else shown, fmt)
    worst = schema.worst_level(report)  # the exit code ignores the display filter
    if worst is not None and LEVEL_ORDER[worst] >= LEVEL_ORDER[fail_on.value]:
        raise typer.Exit(1)
