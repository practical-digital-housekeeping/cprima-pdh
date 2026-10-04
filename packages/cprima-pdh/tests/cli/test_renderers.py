"""Output is the Renderer's job, for every command: a command returns a model, the Renderer prints it.

So every command takes `-f text|json|markdown`, and no command module writes results itself.
"""
import ast
import json
from pathlib import Path

import pytest
import typer
from pdh_testkit import Entry, synthetic_vault
from pdh_testkit.runner import pdh_runner
from typer.testing import CliRunner

from cprima_pdh import session
from cprima_pdh.cli import app

CLI_DIR = Path(__file__).resolve().parents[2] / "src" / "cprima_pdh" / "cli"
ALLOWED_ECHO = {("_common.py", "fail"), ("__init__.py", "_version")}  # an error message; the --version flag


def _leaves(group, prefix=()):
    for name, cmd in sorted(group.commands.items()):
        if hasattr(cmd, "commands"):
            yield from _leaves(cmd, (*prefix, name))
        else:
            yield (*prefix, name), cmd


COMMANDS = list(_leaves(typer.main.get_command(app)))


def test_the_commands_are_found():
    assert len(COMMANDS) >= 25 and ("backends",) in [c[0] for c in COMMANDS]


@pytest.mark.parametrize("path,cmd", COMMANDS, ids=[" ".join(p) for p, _ in COMMANDS])
def test_every_command_has_a_format_option(path, cmd):
    options = {opt for p in cmd.params for opt in getattr(p, "opts", [])}
    assert {"--format", "-f"} <= options, f"`pdh {' '.join(path)}` has no -f/--format"


def _output_calls():
    for file in sorted(CLI_DIR.glob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    f = node.func
                    if (isinstance(f, ast.Attribute) and f.attr == "echo" and getattr(f.value, "id", "") == "typer") or \
                            (isinstance(f, ast.Name) and f.id == "print"):
                        yield file.name, fn.name


def test_no_command_writes_output_itself():
    offenders = sorted({c for c in _output_calls() if c not in ALLOWED_ECHO})
    assert not offenders, f"output must go through the Renderer (c.emit): {offenders}"


# --- the commands that used to print directly ------------------------------------------------------

@pytest.fixture
def run(monkeypatch, tmp_path):
    return pdh_runner(monkeypatch, tmp_path)


@pytest.mark.parametrize("command", [("backends",), ("method", "profiles")])
def test_listing_commands_render_in_every_format(run, command):
    text = run([], *command, with_db=False)
    data = json.loads(run([], *command, "-f", "json", with_db=False).stdout)
    md = run([], *command, "-f", "markdown", with_db=False)
    assert text.exit_code == md.exit_code == 0 and text.stdout.strip() and md.stdout.strip() and data


def test_backends_rows_are_data(run):
    rows = json.loads(run([], "backends", "-f", "json", with_db=False).stdout)["backends"]
    assert any(r["name"] == "kdbx" and r["ready"] for r in rows)
    assert "kdbx" in run([], "backends", with_db=False).stdout


def _state(monkeypatch, left: int):
    monkeypatch.setattr(session, "seconds_left", lambda: left)


def test_session_status_is_a_model_and_the_exit_code_still_says_locked(run, monkeypatch):
    _state(monkeypatch, 0)
    locked = run([], "session", "status", "-f", "json", with_db=False)
    assert locked.exit_code == 1 and json.loads(locked.stdout)["unlocked"] is False
    _state(monkeypatch, 754)
    open_ = run([], "session", "status", "-f", "json", with_db=False)
    data = json.loads(open_.stdout)
    assert open_.exit_code == 0 and data["unlocked"] is True and data["seconds_left"] == 754
    assert "unlocked, 12m34s left" in run([], "session", "status", with_db=False).stdout


def test_session_lock_reports_through_the_renderer(run, monkeypatch):
    monkeypatch.setattr(session, "lock", lambda: True)
    assert json.loads(run([], "session", "lock", "-f", "json", with_db=False).stdout)["action"] == "locked"
    monkeypatch.setattr(session, "lock", lambda: False)
    assert "no session" in run([], "session", "lock", with_db=False).stdout


def test_session_unlock_reports_through_the_renderer(tmp_path, monkeypatch):
    vault = synthetic_vault(tmp_path / "v.kdbx", [Entry("x")])
    saved = {}
    monkeypatch.setattr(session, "save_session", lambda *a: saved.setdefault("args", a))
    monkeypatch.setattr("cprima_pdh.cli._common.prompt_password", lambda: "pdh-test-password")
    result = CliRunner().invoke(app, ["--db", str(vault), "session", "unlock", "--minutes", "5", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and data["action"] == "unlocked" and data["minutes"] == 5 and saved["args"][3] == 5
    assert "pdh-test-password" not in result.stdout  # a password is never part of the output


def test_the_version_flag_is_the_one_allowed_exception():
    assert CliRunner().invoke(app, ["--version"]).stdout.startswith("pdh ")
