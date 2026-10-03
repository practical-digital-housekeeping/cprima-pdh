"""The planned command surface: commands that exist in `--help` and exit 3 until they are built (`(planned)` in their help).

When a command is implemented, remove it from PLANNED, drop the marker from its help, and give it real tests.
"""
import re

import pytest
import typer
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app

# command words -> the arguments it needs to parse (the contract of the planned surface)
PLANNED = {
    ("serve",): ["--port", "8765", "--allow", "Money/Example login"],
}


def leaves():
    def walk(cmd, words):
        subs = getattr(cmd, "commands", None)
        if subs:
            for name, sub in subs.items():
                yield from walk(sub, (*words, name))
        else:
            yield words, cmd

    yield from walk(typer.main.get_command(app), ())


def test_the_planned_surface_is_exactly_the_contract():
    assert {words for words, cmd in leaves() if (cmd.help or "").lstrip().startswith("(planned)")} == set(PLANNED)


@pytest.mark.parametrize("words", sorted(PLANNED), ids=[" ".join(w) for w in sorted(PLANNED)])
def test_a_planned_command_exits_3_and_never_opens_a_vault_or_a_port(words, monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda *_a: pytest.fail("a planned command opened the vault"))
    import socket

    monkeypatch.setattr(socket.socket, "bind", lambda *_a: pytest.fail("a planned command opened a port"))
    result = CliRunner().invoke(app, [*words, *PLANNED[words]])
    assert result.exit_code == _common.NOT_IMPLEMENTED == 3
    assert "not implemented yet" in result.stderr and " ".join(words) in result.stderr


@pytest.mark.parametrize("words", sorted(PLANNED), ids=[" ".join(w) for w in sorted(PLANNED)])
def test_a_planned_command_documents_itself_and_has_a_format_option(words):
    result = CliRunner().invoke(app, [*words, "--help"])
    text = re.sub(r"\[[0-9;]*m", "", result.stdout)  # a CI runner colours the help; the words must still be there
    assert result.exit_code == 0 and "(planned)" in text and "--format" in text


def test_serve_only_accepts_the_options_of_its_contract():
    assert CliRunner().invoke(app, ["serve", "--bind-everything"]).exit_code == 2
