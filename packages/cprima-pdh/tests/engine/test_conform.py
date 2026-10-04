"""`conform`: every entry as conform / nonconform, each issue with an action an agent can act on. No secret values."""
import json

import pytest
from pdh_testkit.runner import pdh_runner
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.conform import conformance
from cprima_pdh.schema import parse_schemas

TOML = """
[field.serial_number]
aliases = ["serialnumber"]
protected = false

[field.PIN]
protected = true

[facet.login]
required = ["Title", "UserName", "Password", "URL"]
https_only = true

[schema.website]
facets = ["login"]

[schema.shop]
facets = ["login"]
recommended = ["customer_no"]
closed = true
expires = true

[schema.card]
required = ["Title"]
"""
SSET = parse_schemas(TOML)


def report(*entries, **kw):
    return conformance(StubKP(list(entries)), SSET, **kw)


def only(rep):
    assert len(rep.entries) == 1
    return rep.entries[0]


# --- status of an entry -----------------------------------------------------------------------

def test_a_clean_typed_entry_conforms():
    rep = report(E(title="a", schema="website"), status="all")
    e = only(rep)
    assert (e.status, e.issues, e.schemas) == ("conform", [], ["website"])


def test_an_entry_with_a_finding_does_not_conform():
    e = only(report(E(schema="website", username=""), status="all"))
    assert e.status == "nonconform"
    assert [i.rule for i in e.issues] == ["required:UserName"]


def test_an_entry_without_schema_and_without_findings_is_unclassified():
    assert only(report(E(), status="all")).status == "unclassified"


def test_an_entry_without_schema_but_with_a_vocabulary_finding_does_not_conform():
    e = only(report(E(custom={"serialnumber": "1"}), status="all"))
    assert e.status == "nonconform" and e.schemas == []


def test_counts_cover_all_entries_even_when_the_list_is_filtered():
    rep = report(E(title="ok", schema="website"), E(title="bad", schema="website", username=""), E(title="x"),
                 status="nonconform")
    assert (rep.conform, rep.nonconform, rep.unclassified) == (1, 1, 1)
    assert [e.entry for e in rep.entries] == ["Area/bad"]


@pytest.mark.parametrize("status,expected", [
    ("conform", ["Area/ok"]), ("nonconform", ["Area/bad"]), ("unclassified", ["Area/x"]),
    ("all", ["Area/bad", "Area/ok", "Area/x"]),
])
def test_status_filter(status, expected):
    rep = report(E(title="ok", schema="website"), E(title="bad", schema="website", username=""), E(title="x"),
                 status=status)
    assert [e.entry for e in rep.entries] == expected


def test_schema_filter_keeps_entries_naming_that_schema():
    rep = report(E(title="a", schema="website"), E(title="b", schema="card"), status="all", only_schema="card")
    assert [e.entry for e in rep.entries] == ["Area/b"]


def test_level_filter_decides_what_counts_as_nonconform():
    entry = E(schema="website", url="http://x.example")  # only a WARN
    assert only(report(entry, status="all", level="ERROR")).status == "conform"
    assert only(report(entry, status="all", level="WARN")).status == "nonconform"


# --- the action per issue ---------------------------------------------------------------------

def issues(entry, **kw):
    return {i.rule: i for i in only(report(entry, status="all", **kw)).issues}


def test_missing_required_needs_a_value_from_the_owner():
    i = issues(E(title="t", schema="website", username=""))["required:UserName"]
    assert (i.action, i.automatable, i.fields, i.level) == ("supply-value", False, ["UserName"], "ERROR")
    assert i.command == 'pdh edit set "Area/t" UserName <value> --apply'


def test_missing_recommended_is_a_warn_with_the_same_action():
    i = issues(E(title="t", schema="shop", expires=True))["recommended:customer_no"]
    assert (i.action, i.level, i.automatable) == ("supply-value", "WARN", False)


def test_alias_is_renamed_automatically():
    i = issues(E(title="t", custom={"serialnumber": "1"}))["alias:serial_number"]
    assert (i.action, i.automatable) == ("rename-field", True)
    assert i.command == 'pdh edit rename-field "Area/t" serialnumber serial_number --apply'


def test_vocabulary_protection_is_fixed_by_fix():
    i = issues(E(custom={"PIN": "1234"}))["protected:PIN"]
    assert (i.action, i.automatable, i.command) == ("protect-field", True, "pdh edit vocabulary --apply")


def test_unsupported_field_name_needs_a_decision():
    i = issues(E(title="t", custom={"Fax": "1"}))["unknown-field"]
    assert (i.action, i.automatable, i.level, i.fields) == ("decide-field", False, "WARN", ["Fax"])


def test_unknown_field_in_a_closed_schema_needs_a_decision():
    i = issues(E(schema="shop", expires=True, custom={"customer_no": "1", "Fax": "2"}))["closed:unknown-field"]
    assert (i.action, i.automatable, i.fields) == ("decide-field", False, ["Fax"])


def test_http_is_only_a_review_hint():
    i = issues(E(schema="website", url="http://x.example"))["url:https"]
    assert (i.action, i.automatable, i.level) == ("review-url", False, "WARN")
    assert "valid" in i.note


def test_missing_expiry_is_set_in_the_client():
    i = issues(E(schema="shop", custom={"customer_no": "1"}))["expires"]
    assert (i.action, i.automatable, i.command) == ("set-expiry", False, None)


def test_unknown_schema_name_is_fixed_with_set():
    i = issues(E(title="t", schema="nope"))["schema:unknown"]
    assert (i.action, i.fields) == ("fix-schema", ["nope"])
    assert i.command == 'pdh edit set "Area/t" _schema <schema> --overwrite --apply'


def test_every_issue_has_a_known_action_and_a_level():
    rep = report(E(title="1", schema="shop", username="", url="http://x", custom={"serialnumber": "1", "Fax": "2",
                                                                                  "PIN": "1"}),
                 E(title="2", schema="nope"), status="all")
    known = {"supply-value", "rename-field", "protect-field", "unprotect-field", "decide-field", "review-url",
             "set-expiry", "fix-schema", "fix-link", "review-value", "review"}
    for e in rep.entries:
        for i in e.issues:
            assert i.action in known and i.level in ("INFO", "WARN", "ERROR") and i.note


def test_no_value_ever_appears():
    entry = E(title="t", password="PW-SENTINEL", schema="website", username="", url="http://x.example",
              custom={"serialnumber": "SERIAL-SENTINEL", "PIN": "PIN-SENTINEL"})
    out = report(entry, status="all").model_dump_json()
    for sentinel in ("PW-SENTINEL", "SERIAL-SENTINEL", "PIN-SENTINEL"):
        assert sentinel not in out


# --- the CLI ----------------------------------------------------------------------------------

@pytest.fixture
def run(monkeypatch, tmp_path):
    inner = pdh_runner(monkeypatch, tmp_path, TOML)
    return lambda entries, *args: inner(entries, "check", "conform", *args)


def test_cli_default_lists_nonconforming_entries_only(run):
    result = run([E(title="ok", schema="website"), E(title="bad", schema="website", username="")])
    assert result.exit_code == 0 and "Area/bad" in result.stdout and "Area/ok" not in result.stdout


def test_cli_json_is_the_agent_interface(run):
    data = json.loads(run([E(title="bad", schema="website", username="")], "--status", "all", "-f", "json").stdout)
    assert {"conform", "nonconform", "unclassified", "entries"} <= set(data)
    issue = data["entries"][0]["issues"][0]
    assert {"rule", "level", "fields", "action", "automatable", "command", "note"} <= set(issue)


def test_cli_conform_status_shows_the_good_ones(run):
    result = run([E(title="ok", schema="website"), E(title="bad", schema="website", username="")], "--status", "conform")
    assert "Area/ok" in result.stdout and "Area/bad" not in result.stdout


def test_cli_rejects_an_unknown_status(run):
    assert run([E()], "--status", "maybe").exit_code != 0
