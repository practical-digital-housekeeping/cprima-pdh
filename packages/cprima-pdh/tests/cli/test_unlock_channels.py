"""The master passphrase of a vault: `--password-stdin`, `KDBX_PASSWORD`, then (as before) the sidecar, the session and a prompt.

One secret that opens a store has its own channels, as a CI system injects it. A wrong passphrase from an explicit channel
is an error, never a fall-back to asking; the passphrase is never printed.
"""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import app
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

WRONG = "not-the-passphrase-xyz"


@pytest.fixture(autouse=True)
def no_ambient_credentials(monkeypatch):
    monkeypatch.delenv("KDBX_PASSWORD", raising=False)  # (the session file is isolated for every test by conftest.py)


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])


def titles(result):
    return sorted(e["title"] for e in json.loads(result.stdout)["entries"])


def entries(vault, *global_options, env=None, input=None):
    return CliRunner().invoke(app, [*global_options, "--db", str(vault), "inspect", "entries", "-f", "json"],
                              env=env, input=input)


def test_the_environment_unlocks(vault):
    result = entries(vault, env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 0 and titles(result) == ["a"]


def test_standard_input_unlocks(vault):
    result = entries(vault, "--password-stdin", input=DEFAULT_PASSWORD + "\n")
    assert result.exit_code == 0 and titles(result) == ["a"]


def test_standard_input_without_a_trailing_newline_unlocks(vault):
    assert entries(vault, "--password-stdin", input=DEFAULT_PASSWORD).exit_code == 0


def test_standard_input_beats_the_environment(vault):
    good_stdin = entries(vault, "--password-stdin", env={"KDBX_PASSWORD": WRONG}, input=DEFAULT_PASSWORD + "\n")
    assert good_stdin.exit_code == 0
    bad_stdin = entries(vault, "--password-stdin", env={"KDBX_PASSWORD": DEFAULT_PASSWORD}, input=WRONG + "\n")
    assert bad_stdin.exit_code == 1 and "open failed" in bad_stdin.stderr


@pytest.mark.parametrize("channel", ["env", "stdin"])
def test_a_wrong_passphrase_is_an_error_and_is_never_printed_or_replaced_by_a_prompt(vault, channel):
    if channel == "env":
        result = entries(vault, env={"KDBX_PASSWORD": WRONG})
    else:
        result = entries(vault, "--password-stdin", input=WRONG + "\n")
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 1 and "open failed" in shown
    assert WRONG not in shown and "no terminal" not in shown  # it did not fall back to asking


def test_an_empty_environment_variable_counts_as_not_set(vault):
    result = entries(vault, env={"KDBX_PASSWORD": ""})
    assert result.exit_code == 2 and "no terminal to ask on" in result.stderr


def test_nothing_given_and_no_terminal_says_what_to_do(vault):
    result = entries(vault)
    assert result.exit_code == 2 and "pdh session unlock" in result.stderr


def test_an_empty_standard_input_is_refused(vault):
    result = entries(vault, "--password-stdin", input="")
    assert result.exit_code == 2 and "--password-stdin" in result.stderr


def test_an_explicit_channel_beats_the_sidecar(vault):
    vault.with_suffix(".toml").write_text(f'password = "{WRONG}"\n', encoding="utf-8")
    assert entries(vault, env={"KDBX_PASSWORD": DEFAULT_PASSWORD}).exit_code == 0


def test_the_sidecar_still_works_without_an_explicit_channel(vault):
    vault.with_suffix(".toml").write_text(f'password = "{DEFAULT_PASSWORD}"\n', encoding="utf-8")
    assert entries(vault).exit_code == 0


def test_write_commands_use_the_same_channels(vault):
    result = CliRunner().invoke(app, ["--db", str(vault), "edit", "new-group", "/", "Money", "--apply"],
                                env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    assert result.exit_code == 0, result.stderr
    assert "Money" in [g.name for g in pykeepass_open(vault, DEFAULT_PASSWORD, None).groups]


def test_doctor_unlocks_with_the_environment_and_never_asks(vault):
    with_env = CliRunner().invoke(app, ["--db", str(vault), "doctor"], env={"KDBX_PASSWORD": DEFAULT_PASSWORD})
    without = CliRunner().invoke(app, ["--db", str(vault), "doctor"])
    assert with_env.exit_code == 0 and without.exit_code == 0
    assert "the passphrase comes from KDBX_PASSWORD" in with_env.stdout
    assert "contents" in with_env.stdout and "needs an unlocked session" in without.stdout
