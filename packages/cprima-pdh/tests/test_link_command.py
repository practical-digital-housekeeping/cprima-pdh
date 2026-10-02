"""`pdh edit link` (set a link, dry run unless --apply) and `pdh inspect links` (the overview). Mocked vault."""
import json

import pytest
from pdh_testkit.runner import pdh_runner
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import make_ref
from cprima_pdh.write import WriteError, plan_link

TOML = """
[field.device]
kind = "link"

[schema.wifi-access-point]
required = ["Title"]

[schema.device-account]
required = ["Title", "device"]
[schema.device-account.links]
device = ["wifi-access-point"]
"""


def pair():
    d = E(title="ap", schema="wifi-access-point")
    a = E(title="acct", schema="device-account", username="u")
    return d, a


# --- planning the write ---------------------------------------------------------------------------

def test_plan_link_sets_a_reference_to_the_target():
    d, a = pair()
    change = plan_link(StubKP([d, a]), "Area/acct", "Area/ap")
    assert (change.entry, change.field, change.action, change.applied) == ("Area/acct", "device", "set", False)
    assert change.new == make_ref(d.uuid) and change.old == ""


def test_plan_link_plain_uses_a_bare_uuid():
    d, a = pair()
    change = plan_link(StubKP([d, a]), "Area/acct", "Area/ap", plain=True)
    assert change.new == str(d.uuid).replace("-", "").upper()


def test_plan_link_custom_field_name():
    d, a = pair()
    assert plan_link(StubKP([d, a]), "Area/acct", "Area/ap", field="host").field == "host"


def test_plan_link_does_not_overwrite_an_existing_link():
    d, a = pair()
    a2 = E(title="acct", schema="device-account", custom={"device": make_ref(d.uuid)})
    change = plan_link(StubKP([d, a2]), "Area/acct", "Area/ap")
    assert change.action == "unchanged"  # same value
    other = E(title="other", schema="wifi-access-point")
    kept = plan_link(StubKP([d, a2, other]), "Area/acct", "Area/other")
    assert kept.action.startswith("skipped")  # differs, and no --overwrite
    assert plan_link(StubKP([d, a2, other]), "Area/acct", "Area/other", overwrite=True).action == "set"


@pytest.mark.parametrize("account,target,fragment", [
    ("Area/nope", "Area/ap", "no entry"),
    ("Area/acct", "Area/nope", "no entry"),
    ("Area/acct", "Area/acct", "itself"),
])
def test_plan_link_refuses(account, target, fragment):
    d, a = pair()
    with pytest.raises(WriteError, match=fragment):
        plan_link(StubKP([d, a]), account, target)


def test_plan_link_refuses_an_ambiguous_target():
    d, a = pair()
    twin = E(title="ap", schema="wifi-access-point")
    with pytest.raises(WriteError, match="2 entries"):
        plan_link(StubKP([d, twin, a]), "Area/acct", "Area/ap")


def test_plan_link_target_can_be_picked_by_username():
    d = E(title="ap", username="one"); twin = E(title="ap", username="two"); a = E(title="acct")
    change = plan_link(StubKP([d, twin, a]), "Area/acct", "Area/ap", target_username="two")
    assert change.new == make_ref(twin.uuid)


# --- the CLI ------------------------------------------------------------------------------------------

@pytest.fixture
def run(monkeypatch, tmp_path):
    inner = pdh_runner(monkeypatch, tmp_path, TOML)
    groups = {"link": "edit", "links": "inspect", "validate": "check"}

    def go(entries, *args):
        return inner(entries, groups[args[0]], *args)

    return go


def test_link_dry_run_shows_the_change_and_writes_nothing(run):
    d, a = pair()
    result = run([d, a], "link", "Area/acct", "Area/ap")
    assert result.exit_code == 0
    assert "applied: False" in result.stdout and make_ref(d.uuid) in result.stdout


def test_link_refusal_exits_2(run):
    d, a = pair()
    result = run([d, a], "link", "Area/acct", "Area/nope")
    assert result.exit_code == 2 and "no entry" in result.stderr


def test_links_lists_relations_as_json(run):
    d, a = pair()
    a.set_link = None
    a = E(title="acct", schema="device-account", username="u", custom={"device": make_ref(d.uuid)})
    data = json.loads(run([d, a], "links", "-f", "json").stdout)
    assert [(l["source"], l["target"], l["status"]) for l in data["links"]] == [("Area/acct", "Area/ap", "ok")]
    assert data["per_target"] == {"Area/ap": 1}


def test_links_marks_a_dangling_link(run):
    d, _ = pair()
    a = E(title="acct", schema="device-account", username="u", custom={"device": make_ref("3F2A9C1E7B4D4E0A8C5D6E7F8091A2B3")})
    data = json.loads(run([d, a], "links", "-f", "json").stdout)
    assert data["links"][0]["status"] == "dangling" and data["links"][0]["target"] is None


def test_validate_reports_a_broken_link_as_an_error(run):
    d, _ = pair()
    a = E(title="acct", schema="device-account", username="u", custom={"device": "garbage"})
    result = run([d, a], "validate")
    assert result.exit_code == 1 and "link" in result.stdout.lower()
