"""What pdh does with the sops layer: the engine validates a sops vault like any other, and the backend is registered."""
from pdh_testkit.sopsfix import load_sops

from cprima_pdh import profiles
from cprima_pdh.backends.sops import Backend
from cprima_pdh.validation import validate_entries
from cprima_pdh_sopskit import age
from cprima_pdh_sopskit.sops_vault import SopsVault

FIX = load_sops("sops-json-basic")


def test_the_engine_validates_a_sops_vault_like_any_other():
    vault = SopsVault.open(FIX.path, age.identities_from_text(FIX.identity_text))
    report = validate_entries(vault.entries(), profiles.load("pdh-default"))
    assert report.unclassified_entries == 5  # no entry names a record type
    assert any(f.rule == "unknown-field" for f in report.findings)  # `customer_no` etc. are not all vocabulary terms


def test_the_backend_reports_its_dependency():
    assert Backend.name == "sops" and Backend.missing_dependencies() == []
