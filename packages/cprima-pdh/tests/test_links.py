"""Relations between entries: a field of kind `link` names another entry by UUID.

Only structure is checked: the link must parse, resolve to a live entry, and that entry must carry one of the
allowed schemas. Nothing judges a value. Written before the implementation (red first).
"""
import json

import pytest
from pdh_testkit.stubs import E, StubGroup, StubKP

from cprima_pdh.schema import SchemaError, make_ref, parse_link, parse_schemas, unclassified, validate

SCHEMAS = parse_schemas("""
[field.device]
kind = "link"
description = "The device an account belongs to."

[schema.wifi-access-point]
required = ["Title"]

[schema.openwrt-device]
required = ["Title"]

[schema.website]
required = ["Title"]

[schema.device-account]
required = ["Title", "UserName", "Password", "device"]
[schema.device-account.links]
device = ["wifi-access-point", "openwrt-device"]
""")

DA = "device-account"
HEX = "3F2A9C1E7B4D4E0A8C5D6E7F8091A2B3"
DASHED = "3f2a9c1e-7b4d-4e0a-8c5d-6e7f8091a2b3"


# --- parsing a link value -----------------------------------------------------------------------

VALID = [
    (f"{{REF:T@I:{HEX}}}", HEX),
    (f"{{REF:U@I:{HEX}}}", HEX),                      # any field code, the target is what counts
    (f"{{ref:t@i:{HEX.lower()}}}", HEX),              # case-insensitive
    (f"  {{REF:T@I:{HEX}}}  ", HEX),                  # surrounding spaces
    (HEX, HEX),                                        # a bare UUID, 32 hex digits
    (HEX.lower(), HEX),
    (DASHED, HEX),                                     # a bare UUID with hyphens
    (DASHED.upper(), HEX),
]
INVALID = ["", "   ", "My Access Point", "{REF:T@T:My Access Point}", f"{{REF:T@I:{HEX[:-1]}}}", HEX[:-1], HEX + "0",
           "{REF:T@I:}", "REF:T@I:" + HEX, f"{{REF:T@I:{'Z' * 32}}}", "3f2a9c1e-7b4d-4e0a-8c5d"]


@pytest.mark.parametrize("raw,expected", VALID, ids=[v[0][:24] or "empty" for v in VALID])
def test_parse_valid_links(raw, expected):
    assert parse_link(raw) == expected


@pytest.mark.parametrize("raw", INVALID)
def test_parse_invalid_links(raw):
    assert parse_link(raw) is None


def test_make_ref_round_trips():
    assert make_ref(DASHED) == f"{{REF:T@I:{HEX}}}"
    assert make_ref(HEX) == f"{{REF:T@I:{HEX}}}"
    assert parse_link(make_ref(DASHED)) == HEX


# --- the checks ---------------------------------------------------------------------------------

def acct(target, field_value=None, schema=DA, **kw):
    """An account entry whose `device` field links to `target` (an entry), or holds `field_value`."""
    value = field_value if field_value is not None else make_ref(target.uuid)
    return E(title="acct", schema=schema, username="u", custom={"device": value}, protected=(), **kw)


def device(schema="wifi-access-point", **kw):
    return E(title="ap", schema=schema, **kw)


def run(entries, kp_kwargs=None):
    report = validate(StubKP(entries, **(kp_kwargs or {})), SCHEMAS)
    return {(f.schema_name, f.rule, f.level) for f in report.findings if f.entry.endswith("/acct")}, report


def case_ok():
    d = device(); return [d, acct(d)], set()


def case_ok_plain_uuid():
    d = device(); return [d, acct(d, field_value=str(d.uuid))], set()


def case_ok_hex_uuid():
    d = device(); return [d, acct(d, field_value=str(d.uuid).replace("-", "").upper())], set()


def case_ok_second_allowed_schema():
    d = device("openwrt-device"); return [d, acct(d)], set()


def case_ok_target_has_several_schemas():
    d = device("website, wifi-access-point"); return [d, acct(d)], set()


def case_ok_target_in_another_group():
    d = device(group="Far/Away"); return [d, acct(d)], set()


def case_dangling():
    d = device(); return [acct(d, field_value=make_ref(DASHED))], {(DA, "link:dangling", "ERROR")}


def case_invalid_format():
    d = device(); return [d, acct(d, field_value="My Access Point")], {(DA, "link:invalid", "ERROR")}


def case_reference_by_title_is_not_supported():
    d = device(); return [d, acct(d, field_value="{REF:T@T:ap}")], {(DA, "link:invalid", "ERROR")}


def case_wrong_schema():
    d = device("website"); return [d, acct(d)], {(DA, "link:wrong-schema", "WARN")}


def case_target_unclassified():
    d = E(title="ap"); return [d, acct(d)], {(DA, "link:target-unclassified", "INFO")}


def case_target_only_unknown_schema():
    d = device("nope"); return [d, acct(d)], {(DA, "link:target-unclassified", "INFO")}


def case_self_link():
    a = acct(None, field_value="x")
    a._element.xpath("String[Key='device']/Value")[0].text = make_ref(a.uuid)
    return [a], {(DA, "link:self", "ERROR")}


def case_missing_field():
    d = device(); a = E(title="acct", schema=DA, username="u"); return [d, a], {(DA, "required:device", "ERROR")}


def case_empty_field():
    d = device(); return [d, acct(d, field_value="")], {(DA, "required:device", "ERROR")}


CASES = [case_ok, case_ok_plain_uuid, case_ok_hex_uuid, case_ok_second_allowed_schema,
         case_ok_target_has_several_schemas, case_ok_target_in_another_group, case_dangling, case_invalid_format,
         case_reference_by_title_is_not_supported, case_wrong_schema, case_target_unclassified,
         case_target_only_unknown_schema, case_self_link, case_missing_field, case_empty_field]


@pytest.mark.parametrize("case", CASES, ids=[c.__name__[5:] for c in CASES])
def test_link_findings(case):
    entries, expected = case()
    assert run(entries)[0] == expected


def test_a_target_in_the_recycle_bin_is_dangling():
    bin_ = StubGroup(["Recycle Bin"])
    d = device(group=bin_)
    found, _ = run([d, acct(d)], {"recyclebin_group": bin_})
    assert found == {(DA, "link:dangling", "ERROR")}


def test_the_link_value_never_appears_in_the_output():
    d = device(); a = acct(d)
    _, report = run([d, a])
    assert str(d.uuid) not in report.model_dump_json()
    d2 = device(); a2 = acct(d2, field_value=make_ref(DASHED))
    _, report2 = run([a2])
    assert HEX not in report2.model_dump_json() and DASHED not in report2.model_dump_json()


def test_an_account_is_still_typed_and_counted():
    d = device(); a = acct(d)
    report = validate(StubKP([d, a]), SCHEMAS)
    assert report.schemas[DA].entries == 1 and report.schemas[DA].conforming == 1
    assert report.unclassified_entries == 0


def test_only_entries_that_name_a_linking_schema_are_checked():
    d = device()
    stray = E(title="acct", custom={"device": "garbage"})  # no _schema: not a device-account, not checked
    assert not [f for f in validate(StubKP([d, stray]), SCHEMAS).findings if f.rule.startswith("link:")]


# --- schema loading: a declared link must make sense ------------------------------------------------

def test_links_must_name_a_vocabulary_term_of_kind_link():
    with pytest.raises(SchemaError):
        parse_schemas("""
[schema.a]
required = ["Title"]
[schema.b]
[schema.b.links]
nonterm = ["a"]
""")
    with pytest.raises(SchemaError):  # the term exists but is not of kind link
        parse_schemas("""
[field.device]
kind = "text"
[schema.a]
[schema.b.links]
device = ["a"]
""")


def test_link_targets_must_be_active_schemas():
    base = """
[field.device]
kind = "link"
[schema.a]
[schema.p]
status = "proposed"
"""
    parse_schemas(base + '[schema.b]\n[schema.b.links]\ndevice = ["a"]\n')
    with pytest.raises(SchemaError):
        parse_schemas(base + '[schema.b]\n[schema.b.links]\ndevice = ["nope"]\n')
    with pytest.raises(SchemaError):  # a proposed schema can never be satisfied
        parse_schemas(base + '[schema.b]\n[schema.b.links]\ndevice = ["p"]\n')


def test_links_merge_through_facets():
    sset = parse_schemas("""
[field.device]
kind = "link"
[schema.ap]
[schema.sw]
[facet.of-a-device]
[facet.of-a-device.links]
device = ["ap"]
[schema.acct]
facets = ["of-a-device"]
[schema.acct.links]
device = ["sw"]
""")
    from cprima_pdh.schema import resolve

    assert resolve(sset.schemas["acct"], sset.facets).links == {"device": ["ap", "sw"]}


def test_a_closed_schema_knows_its_link_field():
    sset = parse_schemas("""
[field.device]
kind = "link"
[schema.ap]
[schema.acct]
closed = true
required = ["Title"]
[schema.acct.links]
device = ["ap"]
""")
    d = E(title="ap", schema="ap")
    a = E(title="acct", schema="acct", custom={"device": make_ref(d.uuid)})
    rules = {(f.schema_name, f.rule) for f in validate(StubKP([d, a]), sset).findings}
    assert ("acct", "closed:unknown-field") not in rules


# --- the `links` overview ----------------------------------------------------------------------------

def test_links_report_lists_each_relation_with_its_status():
    from cprima_pdh.schema import links_report

    d = device(); ok = acct(d); ok2 = E(title="acct2", schema=DA, username="u", custom={"device": make_ref(d.uuid)})
    bad = E(title="acct3", schema=DA, username="u", custom={"device": make_ref(DASHED)})
    report = links_report(StubKP([d, ok, ok2, bad]), SCHEMAS)
    by_source = {l.source: l for l in report.links}
    assert by_source["Area/acct"].target == "Area/ap" and by_source["Area/acct"].status == "ok"
    assert by_source["Area/acct3"].target is None and by_source["Area/acct3"].status == "dangling"
    assert report.per_target == {"Area/ap": 2}
    assert json.loads(report.model_dump_json())["links"]  # serialisable, and holds no raw UUID
    assert DASHED not in report.model_dump_json() and HEX not in report.model_dump_json()


def test_unclassified_is_unaffected_by_links():
    d = device()
    assert unclassified(StubKP([d, acct(d)]), SCHEMAS).total == 0
