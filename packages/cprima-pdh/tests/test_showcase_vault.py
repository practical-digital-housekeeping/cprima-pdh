"""The showcase vault (examples/pdh-default/sample.kdbx): fictional, finished, conforming, and kept in step."""
import re

import pytest
from pdh_testkit import showcase
from pdh_testkit.paths import REPO_ROOT
from pykeepass import PyKeePass

from cprima_pdh import profiles
from cprima_pdh.conform import conformance
from cprima_pdh.schema import typing_of, validate

SSET = profiles.load(profiles.DEFAULT)
VAULT = showcase.EXAMPLE_DIR / f"{showcase.NAME}.kdbx"
SIDECAR = VAULT.with_suffix(".toml")


@pytest.fixture(scope="module")
def kp():
    return PyKeePass(str(VAULT), password=showcase.PASSWORD)


def test_every_entry_conforms_to_the_profile(kp):
    rep = conformance(kp, SSET, status="all")
    assert (rep.nonconform, rep.unclassified) == (0, 0) and rep.conform == len(kp.entries) == len(showcase.ITEMS)
    assert validate(kp, SSET).findings == []  # not even an INFO


def test_every_record_type_and_every_area_is_shown(kp):
    typed = set()
    for e in kp.entries:
        t = typing_of(e, SSET)  # written in `_schema` and/or derived from the fields
        assert not t.unknown and t.names
        typed.update(t.names)
    assert typed == set(SSET.schemas)
    assert {e.group.name for e in kp.entries} == set(SSET.areas)


def by_title(kp, title):
    return typing_of(next(e for e in kp.entries if e.title == title), SSET)


def test_schema_and_field_rules_work_together(kp):
    """The point of the sample: record types come from `_schema` and/or from the fields, and they add up."""
    # written only
    assert by_title(kp, "Example Mail")[:2] == (["website"], [])
    # derived only: no `_schema` at all, the fields say what it is
    for title, derived in [("Example Bank Account", "bank-account"), ("Example Mobile Plan", "sim-card"), ("Hardware Security Key", "hsm"),
                           ("Office Access Point", "wifi-access-point"), ("Example Cloud API", "api-credential"),
                           ("Example Certification Body", "membership"), ("Deploy key example-server", "keypair"),
                           ("Home Router: guest login", "device-account"), ("Electricity Provider", "utility-contract")]:
        entry = next(e for e in kp.entries if e.title == title)
        assert entry.get_custom_property(SSET.binding.field) is None
        assert by_title(kp, title)[:2] == ([], [derived]), title
    # written and derived on one entry: a login that is also a membership
    assert by_title(kp, "Example Airline Miles")[:2] == (["website"], ["membership"])
    # a type that is written and also matched counts once, as written
    assert by_title(kp, "Example Rail Card")[:2] == (["membership"], [])
    # two written types whose requirements add up
    assert by_title(kp, "Home Router")[:2] == (["wifi-access-point", "openwrt-device"], [])


def test_nine_entries_are_typed_by_their_fields_alone(kp):
    assert sum(1 for e in kp.entries if typing_of(e, SSET).by_fields and not typing_of(e, SSET).explicit) == 9


def test_look_alike_types_are_written_not_guessed(kp):
    """A credit card and a debit card differ by one field; the profile never guesses, so both name their type."""
    for title in ("Example Credit Card", "Example Debit Card"):
        assert by_title(kp, title).by_fields == [] and by_title(kp, title).explicit


def test_three_owners_and_areas_below_them(kp):
    owners = {g.name: g for g in kp.root_group.subgroups}
    assert set(owners) == {showcase.PERSON_A, showcase.PERSON_B, showcase.SHARED}
    for owner in owners.values():
        assert owner.subgroups and all(sub.name in SSET.areas for sub in owner.subgroups)
    assert all(e.group.parentgroup.name in owners for e in kp.entries)


def test_it_shows_the_features_of_the_method(kp):
    assert sum(1 for e in kp.entries if e.otp) >= 5                      # one-time passwords
    assert any(e.get_custom_property(SSET.binding.field) == "onlineshop, website" for e in kp.entries)  # two record types
    account = next(e for e in kp.entries if e.title == "Home Router: guest login")
    assert account.get_custom_property("device").startswith("{REF:T@I:")  # a link between records
    assert sum(1 for e in kp.entries if e.expires) == 3                  # cards have a validity
    for e in kp.entries:                                                 # secrets protected, as the vocabulary demands
        for key, term in SSET.fields.items():
            if term.protected is True and e.get_custom_property(key) is not None:
                assert e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key), (e.title, key)


def test_every_expiry_date_is_far_in_the_future(kp):
    """A showcase must not start to warn on its own as time passes."""
    for e in kp.entries:
        if e.expires:
            assert e.expiry_time.year >= 2030


def test_everything_in_it_is_obviously_fictional(kp):
    """Reserved example domains and address blocks only; no real-looking host, address or account name."""
    hosts = re.compile(r"https?://([^/\s]+)")
    for e in kp.entries:
        for value in [e.url or "", e.username or "", e.get_custom_property("email") or "",
                      *(v for v in (e.custom_properties or {}).values())]:
            for host in hosts.findall(value):
                assert host.endswith("example.org") or host.startswith("192.0.2."), (e.title, host)
        for mail in re.findall(r"[\w.+-]+@([\w.-]+)", f"{e.username} {e.get_custom_property('email')}"):
            assert mail == "example.org", (e.title, mail)


def test_the_committed_vault_is_what_the_builder_makes_from_the_current_profile(tmp_path):
    """Fails when a profile changed but the showcase was not regenerated: run `just example`."""
    from test_canonical_vault import _dump  # the same structural dump: everything but the random uuids

    fresh = showcase.build(tmp_path / "fresh.kdbx", SSET)
    assert _dump(PyKeePass(str(fresh), password=showcase.PASSWORD)) == _dump(PyKeePass(str(VAULT), password=showcase.PASSWORD)), \
        "stale: run `just example`"


def test_the_sidecar_says_how_it_was_made_and_pdh_needs_no_prompt():
    from cprima_pdh.source import sidecar_password

    assert sidecar_password(VAULT) == showcase.PASSWORD
    assert "showcase builder" in SIDECAR.read_text(encoding="utf-8")


README = REPO_ROOT / "examples" / "pdh-default" / "README.md"


def test_the_readme_names_the_commands():
    text = README.read_text(encoding="utf-8")
    for command in ("doctor", "check conform", "inspect tree", "inspect read", "inspect links", "just example"):
        assert command in text


def test_the_readmes_doctor_output_is_what_pdh_prints():
    """The `method` block in the README is a snapshot; it must not drift from the real output."""
    from typer.testing import CliRunner

    from cprima_pdh.cli import app

    shown = re.search(r"<!-- doctor:method -->\n```\n(.*?)\n```\n<!-- /doctor:method -->", README.read_text(encoding="utf-8"),
                      re.S).group(1)
    out = CliRunner().invoke(app, ["--db", str(VAULT), "doctor"]).stdout
    real = out[out.index("method\n"):].rstrip("\n")
    assert shown == real, "README snapshot is stale: paste the `method` section of `pdh doctor` into it"


def test_every_command_in_the_readme_runs():
    from typer.testing import CliRunner

    from cprima_pdh.cli import app

    for line in re.findall(r"^pdh --db \S+ (.+)$", README.read_text(encoding="utf-8"), re.M):
        result = CliRunner().invoke(app, ["--db", str(VAULT), *line.split()])
        assert result.exit_code == 0, f"`pdh {line}` failed: {result.stdout[-200:]}"
