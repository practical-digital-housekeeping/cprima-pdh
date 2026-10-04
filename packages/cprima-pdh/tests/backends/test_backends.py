"""Backends are entry-point plugins behind extras; a missing one is reported with its install line."""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cprima_pdh import backends
from cprima_pdh.cli import app

run = CliRunner().invoke


def test_version_names_the_method():
    out = run(app, ["--version"]).stdout
    assert out.startswith("pdh ") and "Practical Digital Housekeeping" in out


def test_kdbx_backend_is_registered_as_an_entry_point():
    assert "kdbx" in {b.name for b in backends.available()}


def test_backend_is_chosen_by_suffix():
    assert backends.for_path(Path("Vault.KDBX")) == "kdbx"


def test_an_unknown_backend_names_its_install_line():
    with pytest.raises(backends.BackendMissing, match=r"cprima-pdh\[bitwarden\]"):
        backends.load("bitwarden")


def test_a_vault_command_without_the_kdbx_extra_names_the_install_line(monkeypatch, tmp_path):
    from cprima_pdh.backends import kdbx

    monkeypatch.setattr(kdbx.Backend, "requires", ("surely_not_installed_module",))
    vault = tmp_path / "v.kdbx"
    vault.write_bytes(b"")  # never opened: the backend check comes first
    result = run(app, ["--db", str(vault), "check", "validate"])
    assert result.exit_code == 2 and "cprima-pdh[kdbx]" in result.stderr


def test_method_commands_work_without_any_backend(monkeypatch):
    from cprima_pdh.backends import kdbx

    monkeypatch.setattr(kdbx.Backend, "requires", ("surely_not_installed_module",))
    result = run(app, ["method", "schemas"])
    assert result.exit_code == 0 and "website" in result.stdout
