"""The profile drives the finding levels and the standard fields; the kdbx backend owns how they are stored.

Profile (store-independent): which levels rules have, which standard fields an entry has and of what kind.
Backend `kdbx` (KeePass-specific): how those fields are stored: attributes, OTP plugin prefixes, protected strings,
references. Nothing is defined in both places and nothing in the engine.
"""
import re
import tomllib
from pathlib import Path

import pytest
from pdh_testkit.paths import TAXONOMY
from pdh_testkit.stubs import E, StubKP

from cprima_pdh import profiles
from cprima_pdh.backends import kdbx
from cprima_pdh_kdbxkit import kdbx_format
from cprima_pdh.schema import SchemaError, parse_schemas, validate

SSET = profiles.load(profiles.DEFAULT)
RAW = tomllib.loads(TAXONOMY.read_text(encoding="utf-8"))
SRC = Path(__file__).resolve().parents[2] / "src" / "cprima_pdh"

# --- finding levels are data -------------------------------------------------------------------------

EXPECTED = [
    ("required:UserName", "ERROR"), ("schema:unknown", "ERROR"), ("link:invalid", "ERROR"), ("link:dangling", "ERROR"),
    ("link:self", "ERROR"), ("recommended:customer_no", "WARN"), ("protected:PIN", "WARN"),
    ("unprotected:customer_no", "WARN"), ("alias:serial_number", "WARN"), ("closed:unknown-field", "WARN"),
    ("unknown-field", "WARN"), ("expires", "WARN"), ("url:https", "WARN"), ("schema:type-conflict", "WARN"),
    ("link:wrong-schema", "WARN"), ("pattern:PIN", "INFO"), ("link:target-unclassified", "INFO"),
]


def test_the_default_profile_states_its_levels_itself():
    assert "level" in RAW and "default" in RAW["level"]


@pytest.mark.parametrize("rule,level", EXPECTED, ids=[r for r, _ in EXPECTED])
def test_the_default_profiles_levels(rule, level):
    assert SSET.levels.of(rule) == level


def test_an_exact_rule_id_beats_its_kind_which_beats_the_default():
    sset = parse_schemas('[level]\ndefault = "INFO"\nrequired = "WARN"\n"required:URL" = "ERROR"\n')
    assert (sset.levels.of("required:URL"), sset.levels.of("required:Title"), sset.levels.of("expires")) == \
           ("ERROR", "WARN", "INFO")


def test_a_taxonomy_changes_the_severity_of_a_finding():
    """The proof that the data drives: the same entry, two taxonomies, two levels."""
    base = '[schema.s]\nrequired = ["Title", "URL"]\n'
    strict = parse_schemas(base)
    lenient = parse_schemas(base + '[level]\ndefault = "WARN"\nrequired = "INFO"\n')
    assert [f.level for f in validate(StubKP([E(schema="s", url="")]), strict).findings] == ["ERROR"]
    assert [f.level for f in validate(StubKP([E(schema="s", url="")]), lenient).findings] == ["INFO"]


@pytest.mark.parametrize("text", ['[level]\nrequired = "FATAL"\n', '[level]\ndefault = 3\n', '[level]\nx = ["a"]\n'])
def test_a_bad_level_is_rejected(text):
    with pytest.raises(SchemaError):
        parse_schemas(text)


def test_a_fragment_without_levels_uses_those_of_the_default_profile():
    sset = parse_schemas('[schema.a]\nrequired = ["Title"]\n')
    assert sset.levels == SSET.levels and sset.standard == SSET.standard


def test_a_packaged_profile_states_levels_and_standard_fields_itself():
    for name in profiles.names():
        raw = tomllib.loads((SRC / "data" / "profiles" / f"{name}.toml").read_text(encoding="utf-8"))
        assert {"level", "standard", "kind"} <= set(raw), f"{name} must state [level], [standard], [kind]: a profile is complete"


# --- standard fields are data, their storage is the backend's ---------------------------------------------

def test_the_standard_fields_of_the_default_profile():
    assert {n: s.kind for n, s in SSET.standard.items()} == {
        "Title": "text", "UserName": "text", "Password": "secret", "URL": "url", "Notes": "text", "otp": "otp"}


def test_a_standard_field_needs_a_known_kind():
    with pytest.raises(SchemaError):
        parse_schemas('[standard.X]\nkind = "nonsense"\n')  # not one of the inherited kinds either


def test_a_closed_type_allows_every_declared_standard_field_and_nothing_else():
    """Wiring: `Barcode` is allowed on a closed type only because the taxonomy declares it as a standard field."""
    closed = '[schema.s]\nrequired = ["Title"]\nclosed = true\n'
    declared = "".join(f'[standard.{n}]\nkind = "{s.kind}"\n' for n, s in SSET.standard.items())  # a table replaces
    without = validate(StubKP([E(schema="s", custom={"Barcode": "1"})]), parse_schemas(closed))
    with_it = validate(StubKP([E(schema="s", custom={"Barcode": "1"})]),
                       parse_schemas(closed + declared + '[standard.Barcode]\nkind = "identifier"\n'))
    assert [f.rule for f in without.findings] == ["closed:unknown-field"] and with_it.findings == []


def test_a_standard_table_replaces_the_inherited_one():
    """Profiles are complete: a taxonomy that states [standard] states all of it."""
    sset = parse_schemas('[standard.Title]\nkind = "text"\n')
    assert list(sset.standard) == ["Title"]


def test_the_backend_maps_every_standard_field_of_the_profile():
    """A profile cannot declare a standard field the kdbx backend does not know how to store."""
    assert set(SSET.standard) == set(kdbx_format.STANDARD_ATTR)


def test_the_backend_stores_every_field_kind_of_the_profile():
    assert set(SSET.kinds) == set(kdbx.KIND_STORAGE)


# --- the field kinds are data too ------------------------------------------------------------------------

def test_the_engine_has_no_list_of_kinds():
    import cprima_pdh.schema as engine

    assert not hasattr(engine, "KINDS") and not hasattr(engine, "Kind")


TAG = '[kind.tag]\ndescription = "x"\n[standard.Title]\nkind = "tag"\n'  # a complete little taxonomy: kinds + standard


def test_a_taxonomy_declares_its_own_kinds():
    sset = parse_schemas(TAG + '[field.t]\nkind = "tag"\n')
    assert list(sset.kinds) == ["tag"] and sset.fields["t"].kind == "tag"  # a kinds table replaces the inherited one


def test_a_field_or_standard_field_of_an_undeclared_kind_is_rejected():
    with pytest.raises(SchemaError, match="nope"):
        parse_schemas(TAG + '[field.t]\nkind = "nope"\n')
    with pytest.raises(SchemaError, match="nope"):
        parse_schemas('[kind.tag]\ndescription = "x"\n[standard.T]\nkind = "nope"\n')
    with pytest.raises(SchemaError, match="unknown kind 'text'"):  # kinds replaced: the inherited standard fields no longer fit
        parse_schemas('[kind.tag]\ndescription = "x"\n')


def test_fragments_inherit_the_kinds_of_the_default_profile():
    assert list(parse_schemas("").kinds) == list(SSET.kinds)


def test_the_behaviour_of_a_kind_is_data_not_its_name():
    """A kind makes a field a link by saying `behaviour = "link"`; the name `link` alone does nothing."""
    std = '[standard.Title]\nkind = "text"\n'
    works = ('[kind.text]\ndescription = "x"\n[kind.ref]\ndescription = "x"\nbehaviour = "link"\n' + std +
             '[field.target]\nkind = "ref"\n[schema.a]\n[schema.a.links]\ntarget = ["a"]\n')
    assert parse_schemas(works).schemas["a"].links == {"target": ["a"]}
    with pytest.raises(SchemaError, match="link"):
        parse_schemas('[kind.text]\ndescription = "x"\n[kind.link]\ndescription = "x"\n' + std +
                      '[field.target]\nkind = "link"\n[schema.a]\n[schema.a.links]\ntarget = ["a"]\n')


def test_an_unknown_behaviour_is_rejected():
    with pytest.raises(SchemaError):
        parse_schemas('[kind.k]\ndescription = "x"\nbehaviour = "teleport"\n')


def test_the_default_profile_gives_only_its_link_kind_a_behaviour():
    assert {k for k, d in SSET.kinds.items() if d.behaviour} == {"link"}


# --- what to do about a finding is data: `[advice.*]` -------------------------------------------------------

ADVICE_ACTIONS = ["supply-value", "rename-field", "protect-field", "unprotect-field", "decide-field", "review-url",
                  "set-expiry", "fix-schema", "fix-link", "review-value"]


def test_the_default_profile_advises_every_kind_of_finding():
    assert {a.action for a in SSET.advice.values()} >= set(ADVICE_ACTIONS)
    assert "default" in SSET.advice


def test_the_engine_names_no_action():
    src = (SRC / "conform.py").read_text(encoding="utf-8")
    assert not [a for a in ADVICE_ACTIONS if f'"{a}"' in src], "actions belong to the profile's [advice.*]"


def test_a_taxonomy_changes_the_advice():
    from pdh_testkit.stubs import E, StubKP

    from cprima_pdh.conform import conformance

    base = '[schema.s]\nrequired = ["Title", "URL"]\n[advice.default]\naction = "review"\n'
    custom = base + ('[advice.required]\naction = "ask-owner"\nautomatable = false\n'
                     'command = "do {entry} {term}"\nnote = "n {term}"\n')
    kp = StubKP([E(schema="s", url="")])
    plain = conformance(kp, parse_schemas(base)).entries[0].issues[0]
    own = conformance(kp, parse_schemas(custom)).entries[0].issues[0]
    assert plain.action == "review" and plain.command is None
    assert (own.action, own.note) == ("ask-owner", "n URL")
    assert own.command.startswith('do "') and own.command.endswith('" URL')


def test_the_most_specific_advice_wins():
    from pdh_testkit.stubs import E, StubKP

    from cprima_pdh.conform import conformance

    text = ('[schema.s]\nrequired = ["Title", "URL"]\n[advice.default]\naction = "d"\n'
            '[advice.required]\naction = "kind"\n["advice"."required:URL"]\naction = "exact"\n')
    issue = conformance(StubKP([E(schema="s", url="")]), parse_schemas(text)).entries[0].issues[0]
    assert issue.action == "exact"


def test_an_advice_table_needs_a_default():
    with pytest.raises(SchemaError, match="default"):
        parse_schemas('[advice.required]\naction = "x"\n')


# --- the binding field is data: `[binding]` ----------------------------------------------------------------

def test_the_default_profile_binds_record_types_in_the_field_schema():
    assert SSET.binding.field == "_schema"


def test_a_taxonomy_names_its_own_binding_field():
    from pdh_testkit.stubs import E, StubKP

    from cprima_pdh.schema import typing_of

    sset = parse_schemas('[binding]\nfield = "_type"\n[schema.s]\nrequired = ["Title"]\n')
    assert typing_of(E(custom={"_type": "s"}), sset).names == ["s"]
    assert typing_of(E(custom={"_schema": "s"}), sset).names == []  # the old name binds nothing
    other = [f.rule for f in validate(StubKP([E(custom={"_type": "s"})]), sset).findings]
    assert "unknown-field" not in other  # the binding field itself is never an unknown field


def test_advice_commands_use_the_binding_field_of_the_taxonomy():
    from pdh_testkit.stubs import E, StubKP

    from cprima_pdh.conform import conformance

    sset = parse_schemas('[binding]\nfield = "_type"\n[advice.default]\naction = "x"\n'
                         '[advice."schema:unknown"]\naction = "fix-schema"\ncommand = "set {entry} {binding} <schema>"\n')
    issue = conformance(StubKP([E(custom={"_type": "nope"})]), sset).entries[0].issues[0]
    assert issue.command.endswith(" _type <schema>")


def test_the_binding_field_is_stated_by_every_packaged_profile():
    for name in profiles.names():
        raw = tomllib.loads((SRC / "data" / "profiles" / f"{name}.toml").read_text(encoding="utf-8"))
        assert "binding" in raw, f"{name} must state [binding]"


def test_no_code_names_the_binding_field():
    kit = SRC.parents[3] / "pdh-testkit" / "src"
    offenders = [p.name for p in [*SRC.rglob("*.py"), *kit.rglob("*.py")]
                 if re.search(r"""["']_schema["']""", p.read_text(encoding="utf-8"))]
    assert not offenders, offenders


# --- example values are data: a term's own, else its kind's -----------------------------------------------

def test_every_term_has_an_example_and_it_fits_its_pattern():
    for name, ft in SSET.fields.items():
        if SSET.is_link(name):
            continue  # a link holds a reference to a real entry; there is no fake value for it
        value = SSET.example_of(name)
        assert value, f"field.{name} has no example (neither its own nor its kind's)"
        if ft.pattern:
            assert re.fullmatch(ft.pattern, value), f"example of {name} does not fit its pattern"


def test_every_standard_field_has_an_example():
    assert all(SSET.example_of_standard(n) for n in SSET.standard)


def test_a_term_example_beats_its_kind_example():
    sset = parse_schemas('[kind.text]\ndescription = "x"\nexample = "k"\n[standard.Title]\nkind = "text"\n'
                         '[field.a]\nkind = "text"\nexample = "own"\n[field.b]\nkind = "text"\n')
    assert (sset.example_of("a"), sset.example_of("b")) == ("own", "k")


def test_an_example_that_breaks_its_pattern_is_rejected():
    with pytest.raises(SchemaError, match="example"):
        parse_schemas('[field.a]\npattern = "[0-9]+"\nexample = "abc"\n')


def test_the_test_kit_keeps_no_value_tables():
    import pdh_testkit.canonical as canonical

    assert not hasattr(canonical, "VALUES") and not hasattr(canonical, "KIND_FALLBACK")


# --- where a record type belongs: the area is data ---------------------------------------------------------

def test_every_record_type_of_the_default_profile_names_its_area():
    assert {n: s.area for n, s in SSET.schemas.items() if s.area is None} == {}
    assert {s.area for s in SSET.schemas.values()} <= set(SSET.areas)


def test_an_unknown_area_is_rejected():
    with pytest.raises(SchemaError, match="Nowhere"):
        parse_schemas('[area.Somewhere]\ndescription = "x"\n[schema.a]\narea = "Nowhere"\n')


def test_the_test_kit_keeps_no_area_table():
    import pdh_testkit.canonical as canonical

    assert not hasattr(canonical, "AREA_OF")


def test_protected_standard_fields_are_those_whose_kind_is_a_secret():
    secret_kinds = {k for k, d in SSET.kinds.items() if d.default_protected}
    assert set(kdbx_format.STANDARD_PROTECTED) == {n for n, s in SSET.standard.items() if s.kind in secret_kinds}


def test_the_otp_plugin_prefixes_and_their_styles():
    assert kdbx_format.OTP_PREFIXES == ("TimeOtp-", "HmacOtp-")
    assert kdbx_format.OTP_STYLES == {"TimeOtp-": "TimeOtp", "HmacOtp-": "HmacOtp"}


# --- nothing is defined twice ---------------------------------------------------------------------------

def _sources():
    for p in sorted(SRC.rglob("*.py")):
        if p.name not in ("kdbx.py", "kdbx_format.py"):  # the KDBX backend's own files
            yield p, p.read_text(encoding="utf-8")


@pytest.mark.parametrize("literal", ['"TimeOtp-"', '"HmacOtp-"', '"TimeOtp"', '"HmacOtp"'])
def test_keepass_otp_specifics_live_only_in_the_kdbx_backend(literal):
    assert not [p.name for p, text in _sources() if literal in text], literal


def test_the_standard_attribute_mapping_lives_only_in_the_kdbx_backend():
    pattern = re.compile(r'"UserName"\s*:\s*"username"')
    assert not [p.name for p, text in _sources() if pattern.search(text)]


def test_no_level_is_decided_in_code():
    """Severities come from the profile: the engine never names a rule id together with a level."""
    pattern = re.compile(r'(return\s+|\blevel\s*=\s*)"(ERROR|WARN|INFO)"')
    offenders = [p.name for p, text in _sources() if pattern.search(text)]
    assert not offenders, offenders
