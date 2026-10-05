"""`pdh session`: cache the master password for a while (Windows DPAPI), so later commands don't ask."""
from __future__ import annotations

from typing import Annotated

import typer
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

from .. import session as session_mod
from ..models import SessionState
from ..render import Format
from . import _common as c

app = typer.Typer(no_args_is_help=True, help="Unlock once, then work without prompts.")


@app.command()
def unlock(
    ctx: typer.Context,
    fmt: c.Fmt = Format.text,
    minutes: Annotated[int, typer.Option(help="Session lifetime.")] = 30,
) -> None:
    """Prompt once and cache the credentials so later commands don't ask."""
    if not session_mod.supported():
        c.fail("session unlock needs Windows (the cache is encrypted with DPAPI); elsewhere give the passphrase with "
               "KDBX_PASSWORD or --password-stdin", 2)
    st = c.state(ctx)
    db = c.require_db(st)
    c.require_backend("kdbx")
    password = c.prompt_password()
    try:
        pykeepass_open(db, password, str(st.key) if st.key else None)  # verify first
    except Exception as exc:
        c.fail(f"open failed: {exc}", 1)
    session_mod.save_session(db, password, st.key, minutes)
    c.emit(SessionState(action="unlocked", unlocked=True, minutes=minutes, seconds_left=minutes * 60), fmt)


@app.command()
def lock(fmt: c.Fmt = Format.text) -> None:
    """Discard the cached session."""
    done = session_mod.lock()
    c.emit(SessionState(action="locked" if done else "no-session", unlocked=False), fmt)


@app.command()
def status(fmt: c.Fmt = Format.text) -> None:
    """Show session state (exit 1 when locked)."""
    left = session_mod.seconds_left()
    c.emit(SessionState(action="status", unlocked=bool(left), seconds_left=left), fmt)
    if not left:
        raise typer.Exit(1)
