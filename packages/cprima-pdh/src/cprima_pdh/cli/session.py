"""`pdh session`: cache the master password for a while (Windows DPAPI), so later commands don't ask."""
from __future__ import annotations

from typing import Annotated

import typer

from .. import session as session_mod
from .. import source
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Unlock once, then work without prompts.")


@app.command()
def unlock(ctx: typer.Context, minutes: Annotated[int, typer.Option(help="Session lifetime.")] = 30) -> None:
    """Prompt once and cache the credentials so later commands don't ask."""
    st = c.state(ctx)
    db = c.require_db(st)
    c.require_backend("kdbx")
    password = c.prompt_password()
    try:
        source.pykeepass_open(db, password, str(st.key) if st.key else None)  # verify first
    except Exception as exc:
        c.fail(f"open failed: {exc}", 1)
    session_mod.save_session(db, password, st.key, minutes)
    typer.echo(f"unlocked for {minutes} min", err=True)


@app.command()
def lock() -> None:
    """Discard the cached session."""
    typer.echo("locked" if session_mod.lock() else "no session", err=True)


@app.command()
def status() -> None:
    """Show session state (exit 1 when locked)."""
    left = session_mod.seconds_left()
    if not left:
        c.fail("locked", 1)
    typer.echo(f"unlocked, {left // 60}m{left % 60:02d}s left", err=True)
