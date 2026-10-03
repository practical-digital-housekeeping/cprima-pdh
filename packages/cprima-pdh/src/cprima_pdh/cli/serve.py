"""`pdh serve`: a local HTTP API over an unlocked vault. PLANNED: the options are the contract, the body does nothing yet.

Intended design (not built): bound to 127.0.0.1 only, every request needs a token, read-only by default, a fixed small
set of endpoints (entry list without secrets, one-time-password code and remaining seconds), an explicit list of the
entries a token may reach, and a log of who asked for what. A one-time-password code is a credential for 30 seconds, so a
server that hands out codes next to the passwords weakens the second factor: it stays opt-in and local.
Exit code 3 and no vault is opened until it is implemented.
"""
from __future__ import annotations

from typing import Annotated, Optional

import typer

from . import _common as c


def serve(
    fmt: c.Fmt = c.Format.text,
    host: Annotated[str, typer.Option("--host", help="Address to bind; only a loopback address is accepted.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to listen on.")] = 8765,
    token_env: Annotated[str, typer.Option("--token-env", help="Environment variable holding the access token.")] = "PDH_SERVE_TOKEN",
    allow: Annotated[Optional[list[str]], typer.Option("--allow", help="An entry (`group/path/title`) the token may reach; "
                                                                      "repeat for several. Nothing else is served.")] = None,
) -> None:
    """(planned) Serve one-time-password codes and secret-free entry data over local HTTP, for scripts and agents."""
    c.fail("pdh serve: not implemented yet", c.NOT_IMPLEMENTED)
