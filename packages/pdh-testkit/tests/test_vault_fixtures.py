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
def test_it_opens_with_its_own_password(vault):
    kp = PyKeePass(str(vault.path), password=vault.password)
    assert kp.kdbx.body.payload.xml.findtext("Meta/Generator") == vault.client
