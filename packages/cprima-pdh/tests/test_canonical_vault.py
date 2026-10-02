"""The canonical vault: one entry per record type of the default profile, all conforming, kept in step with it.

It is a genuine KeePassXC template filled by pdh-testkit (see its sidecar): fine for these tests, never for
end-to-end tests.
"""
import json

import pytest
from pdh_testkit import canonical, vaults
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh import profiles
from cprima_pdh.cli import app
from cprima_pdh.conform import conformance
from cprima_pdh.schema import parse_schema_names, validate

SSET = profiles.load(profiles.DEFAULT)
VAULT = vaults.load(canonical.NAME)


@pytest.fixture(scope="module")
def kp():
    return PyKeePass(str(VAULT.path), password=VAULT.password)


def test_it_says_how_it_was_made():
    assert not VAULT.genuine and "canonical builder" in VAULT.filled_by
    assert VAULT.path not in [v.path for v in vaults.genuine_vaults()]


def test_every_entry_conforms_to_the_default_profile(kp):
    rep = conformance(kp, SSET, status="all")
    assert (rep.nonconform, rep.unclassified) == (0, 0) and rep.conform == len(kp.entries) > 0
    assert validate(kp, SSET).findings == []  # not even an INFO


def test_every_record_type_has_a_canonical_entry(kp):
    typed = set()
    for e in kp.entries:
        names, unknown = parse_schema_names(e.get_custom_property(SSET.binding.field), SSET.schemas)
        assert not unknown
        typed.update(names)
    assert typed == set(SSET.schemas)


def test_the_match_rules_fire_for_their_own_type_and_for_no_other(kp):
    """Strip the `_schema` from each canonical entry (in memory): the fields alone must bind exactly its own type,
    when the profile has a rule for it, and never a type it does not have."""
    from cprima_pdh.schema import typing_of

    ruled = {m.schema_name for m in SSET.matches}
    for e in kp.entries:
        own = e.get_custom_property(SSET.binding.field)
        written = typing_of(e, SSET)
        assert written.by_fields == [], f"{e.title}: a rule bound {written.by_fields} next to {own!r}"
        e.delete_custom_property(SSET.binding.field)
        derived = typing_of(e, SSET).by_fields
        e.set_custom_property(SSET.binding.field, own)  # back to what it was
        expected = [own] if own in ruled else []
        assert derived == expected, (e.title, derived, expected)


def test_every_match_rule_is_reachable(kp):
    """A rule whose fields no entry of its type can have would never fire."""
    from cprima_pdh.schema import present_fields

    fields = {e.get_custom_property(SSET.binding.field): present_fields(e, SSET.binding.field) for e in kp.entries}  # the canonical entry per type
    for m in SSET.matches:
        assert set(m.has) <= fields[m.schema_name], f"the canonical {m.schema_name} entry cannot satisfy {m.has}"


def test_one_entry_combines_two_record_types(kp):
    combined = [e for e in kp.entries if e.get_custom_property(SSET.binding.field) == "onlineshop, website"]
    assert len(combined) == 1


def test_every_area_is_a_group_below_the_owner_and_every_entry_sits_in_one(kp):
    owner = kp.find_groups(name=canonical.OWNER, first=True)
    assert {g.name for g in owner.subgroups} == set(SSET.areas)
    for e in kp.entries:
        assert e.group.parentgroup.name == canonical.OWNER and e.group.name in SSET.areas


def test_secrets_are_protected_and_links_resolve(kp):
    for e in kp.entries:
        for key, term in SSET.fields.items():
            if term.protected is True and e.get_custom_property(key) is not None:
                assert e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key), (e.title, key)
    account = next(e for e in kp.entries if e.get_custom_property(SSET.binding.field) == "device-account")
    assert account.get_custom_property("device").startswith("{REF:T@I:")


def test_cards_have_an_expiry_date(kp):
    cards = [e for e in kp.entries if e.get_custom_property(SSET.binding.field) in ("credit-card", "bank-card")]
    assert len(cards) == 2 and all(e.expires for e in cards)


def _dump(kp):
    """Everything that matters, without uuids (those change on every build)."""
    out = []
    for e in kp.entries:
        refs = {k: ("<ref>" if v.startswith("{REF:") else v) for k, v in (e.custom_properties or {}).items()}
        out.append((tuple(e.group.path), e.title, e.username, e.password, e.url, e.notes, bool(e.expires),
                    sorted(refs.items()),
                    sorted(k for k in refs if e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=k))))
    return sorted(out, key=repr)


def test_the_committed_vault_is_what_the_builder_makes_from_the_current_profile(tmp_path):
    """Fails when a profile changed but the canonical vault was not regenerated: run `just canonical`."""
    fresh = canonical.build(tmp_path / "fresh.kdbx", SSET)
    assert _dump(PyKeePass(str(fresh), password=canonical.PASSWORD)) == \
        _dump(PyKeePass(str(VAULT.path), password=VAULT.password)), "stale: run `just canonical`"


def test_the_cli_reads_it_through_its_sidecar_without_a_prompt():
    result = CliRunner().invoke(app, ["--db", str(VAULT.path), "check", "conform", "--status", "all", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and data["nonconform"] == 0 and data["conform"] == len(SSET.schemas) + 1
