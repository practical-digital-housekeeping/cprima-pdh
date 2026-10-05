"""A second profile, `pdh-minimal`: proof that nothing outside a profile file is tied to `pdh-default`.

It has its own binding field, areas, record types, vocabulary, levels and advice. The same engine, test kit and CLI
work on it unchanged, and a vault built for one profile is simply not typed under the other: profiles never merge.
"""
import json

import pytest
from pdh_testkit import canonical
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh import profiles
from cprima_pdh.backends import kdbx, kdbx_format
from cprima_pdh.cli import app
from cprima_pdh.conform import conformance
from cprima_pdh.schema import typing_of, validate

DEFAULT = profiles.load("pdh-default")
MINIMAL = profiles.load("pdh-minimal")


@pytest.fixture(scope="module")
def vault(tmp_path_factory):
    dest = tmp_path_factory.mktemp("minimal") / "minimal.kdbx"
    canonical.build(dest, MINIMAL)
    canonical.write_sidecar(dest)
    return dest


@pytest.fixture(scope="module")
def kp(vault):
    return PyKeePass(str(vault), password=canonical.PASSWORD)


def test_both_profiles_are_packaged_and_listed():
    assert profiles.names() == ["pdh-default", "pdh-minimal"]
    out = CliRunner().invoke(app, ["method", "profiles"]).stdout
    assert "pdh-default" in out and "pdh-minimal" in out


def test_the_two_profiles_share_nothing_that_defines_a_type():
    assert MINIMAL.binding.field != DEFAULT.binding.field
    assert not set(MINIMAL.areas) & set(DEFAULT.areas) - {"Money"}
    assert set(MINIMAL.schemas) & set(DEFAULT.schemas) == set()
    assert MINIMAL.profile.full_name == "pdh-minimal"


def test_a_profile_only_uses_what_the_kdbx_backend_can_store():
    for sset in (DEFAULT, MINIMAL):
        assert set(sset.kinds) <= set(kdbx.KIND_STORAGE)
        assert set(sset.standard) <= set(kdbx_format.STANDARD_ATTR)


def test_the_engine_checks_a_vault_against_the_minimal_profile(kp):
    report = conformance(kp, MINIMAL, status="all")
    assert (report.nonconform, report.unclassified) == (0, 0) and report.conform == len(kp.entries) == len(MINIMAL.schemas)
    assert validate(kp, MINIMAL).findings == []


def test_every_entry_sits_in_the_area_its_record_type_names(kp):
    for e in kp.entries:
        names = typing_of(e, MINIMAL).names
        assert e.group.name == MINIMAL.schemas[names[0]].area


def test_entries_are_bound_by_the_minimal_binding_field(kp):
    assert all(e.get_custom_property("_type") for e in kp.entries)
    assert not any(e.get_custom_property("_schema") for e in kp.entries)


def test_its_match_rule_types_an_entry_by_its_fields_alone(kp):
    account = next(e for e in kp.entries if e.get_custom_property("_type") == "account")
    account.delete_custom_property("_type")
    t = typing_of(account, MINIMAL)
    account.set_custom_property("_type", "account")  # the fixture is shared: back to what it was
    assert (t.explicit, t.by_fields) == ([], ["account"])


def test_the_same_vault_is_untyped_under_the_default_profile(kp):
    """No merging: under pdh-default these entries name their types in `_type`, which that profile does not read."""
    assert all(typing_of(e, DEFAULT).names == [] for e in kp.entries)  # no record type, written or by fields
    assert conformance(kp, DEFAULT, status="all").conform == 0


def test_its_own_levels_and_advice_apply(kp):
    from pdh_testkit.stubs import E, StubKP

    kp_ = StubKP([E(custom={"_type": "nope"}), E(custom={"_type": "login"}, url="")])
    findings = {(f.rule, f.level) for f in validate(kp_, MINIMAL).findings}
    assert ("schema:unknown", "ERROR") in findings and ("required:URL", "ERROR") in findings
    issue = conformance(StubKP([E(custom={"_type": "nope"})]), MINIMAL).entries[0].issues[0]
    assert issue.action == "fix-schema" and " _type <type> " in issue.command


def test_the_cli_selects_it_with_the_profile_option(vault):
    args = ["--db", str(vault), "--profile", "pdh-minimal", "check", "conform", "--status", "all", "-f", "json"]
    result = CliRunner().invoke(app, args)
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and data["nonconform"] == 0 and data["conform"] == len(MINIMAL.schemas)


def test_the_cli_shows_its_document(vault):
    out = CliRunner().invoke(app, ["--profile", "pdh-minimal", "method", "show"]).stdout
    assert "pdh-minimal" in out and "## Record types" in out
