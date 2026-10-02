"""The placeholder release: final command shape, no vault access."""
from pathlib import Path

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


def test_check_never_opens_the_file(tmp_path):
    missing = tmp_path / "does-not-exist.kdbx"  # would fail loudly if anything tried to open it
    result = run(app, ["check", str(missing)])
    assert result.exit_code == 0 and "not implemented yet" in result.stdout and "was not opened" in result.stdout


def test_unknown_backend_names_the_install_line(tmp_path):
    result = run(app, ["check", str(tmp_path / "x.bitwarden")])
    assert result.exit_code == 2 and 'cprima-pdh[bitwarden]' in result.stderr


def test_missing_dependency_names_the_install_line(monkeypatch, tmp_path):
    from cprima_pdh.backends import kdbx

    monkeypatch.setattr(kdbx.Backend, "requires", ("surely_not_installed_module",))
    result = run(app, ["check", str(tmp_path / "v.kdbx")])
    assert result.exit_code == 2 and 'cprima-pdh[kdbx]' in result.stderr
