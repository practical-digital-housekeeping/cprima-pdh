"""Every genuine vault fixture has a sidecar, opens with its own password, and is the format its sidecar declares."""
import pytest
from pykeepass import PyKeePass

from pdh_testkit import vaults

FILES = sorted(vaults.VAULT_DIR.glob("*.kdbx"))
SIDECARS = sorted(vaults.VAULT_DIR.glob("*.toml"))


def test_there_are_vault_fixtures():
    assert FILES


@pytest.mark.parametrize("path", FILES, ids=[p.stem for p in FILES])
def test_every_vault_has_a_sidecar(path):
    assert path.with_suffix(".toml").is_file(), f"{path.name} needs {path.stem}.toml"


@pytest.mark.parametrize("path", SIDECARS, ids=[p.stem for p in SIDECARS])
def test_every_sidecar_has_a_vault(path):
    assert path.with_suffix(".kdbx").is_file(), f"{path.name} describes a missing vault"


@pytest.mark.parametrize("vault", vaults.all_vaults(), ids=lambda v: v.name)
def test_the_header_is_the_declared_format(vault):
    assert vaults.header_format(vault.path) == vault.format


def test_templates_are_genuine_and_a_filled_vault_says_otherwise():
    by_name = {v.name: v for v in vaults.all_vaults()}
    assert by_name["template-kdbx4"].genuine and by_name["template-kdbx3"].genuine
    assert not by_name["canonical-kdbx4"].genuine
    assert {v.name for v in vaults.genuine_vaults()} == {n for n, v in by_name.items() if not v.filled_by}


@pytest.mark.parametrize("vault", vaults.all_vaults(), ids=lambda v: v.name)
def test_it_opens_with_its_own_password_and_key_file_if_it_has_one(vault):
    kp = PyKeePass(str(vault.path), password=vault.password, keyfile=str(vault.keyfile) if vault.keyfile else None)
    assert kp.kdbx.body.payload.xml.findtext("Meta/Generator") == vault.client


def test_a_vault_with_a_key_file_does_not_open_without_it():
    vault = vaults.load("keyfile-kdbx4")
    assert vault.keyfile is not None and vault.genuine and vault.format == "KDBX 4.0"
    with pytest.raises(Exception):
        PyKeePass(str(vault.path), password=vault.password)
    with pytest.raises(Exception):
        PyKeePass(str(vault.path), keyfile=str(vault.keyfile))  # and the key file alone does not open it either
