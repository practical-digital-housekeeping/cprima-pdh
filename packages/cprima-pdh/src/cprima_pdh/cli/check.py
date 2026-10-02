"""`pdh check`: does the vault conform to the method? Read-only."""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Optional

import typer

from .. import conform as conform_mod
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
    kp = c.open_db(c.require_db(st), st.key)
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
    report = schema.validate(c.open_db(c.require_db(st), st.key), c.load_taxonomy(st))
    shown = schema.filter_level(report, level.value)
    c.emit(schema.summarize(shown) if summary else shown, fmt)
    worst = schema.worst_level(report)  # the exit code ignores the display filter
    if worst is not None and LEVEL_ORDER[worst] >= LEVEL_ORDER[fail_on.value]:
        raise typer.Exit(1)
