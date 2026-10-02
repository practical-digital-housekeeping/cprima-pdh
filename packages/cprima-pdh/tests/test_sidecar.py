"""A vault with a sidecar `<vault>.toml` holding a `password` opens without a prompt and without a session."""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh import source
from cprima_pdh.cli import app


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("Shop", username="u", password="p")])


def never_prompt():
    pytest.fail("prompted although a sidecar password exists")


def test_no_sidecar_means_no_password(vault):
    assert source.sidecar(vault) is None and source.sidecar_password(vault) is None


def test_sidecar_password_opens_without_prompt(vault):
    vault.with_suffix(".toml").write_text(f'password = "{DEFAULT_PASSWORD}"\nclient = "x"\n', encoding="utf-8")
    assert len(source.open_db(vault, None, never_prompt).entries) == 1


@pytest.mark.parametrize("text", ['client = "only metadata"\n', 'password = 42\n', 'not toml = = ='])
def test_a_sidecar_without_a_usable_password_is_ignored(vault, text):
    vault.with_suffix(".toml").write_text(text, encoding="utf-8")
    assert source.sidecar(vault) is None


def test_a_wrong_sidecar_password_is_an_open_error(vault):
    vault.with_suffix(".toml").write_text('password = "wrong"\n', encoding="utf-8")
    with pytest.raises(source.OpenError):
        source.open_db(vault, None, never_prompt)


def test_cli_reads_a_fixture_vault_without_any_prompt(vault):
    vault.with_suffix(".toml").write_text(f'password = "{DEFAULT_PASSWORD}"\n', encoding="utf-8")
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", "entries"], input="")
    assert result.exit_code == 0 and "Shop" in result.stdout
