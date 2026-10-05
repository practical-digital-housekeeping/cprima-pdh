"""Schemas: defined in TOML, compiled to XPath rules, evaluated on the KDBX XML tree.

Three layers, all in one TOML file:
  [field.NAME]      reusable field type: optional value pattern, protected flag
  [facet.NAME]      reusable group of field rules; a schema mixes facets in via `facets = [...]`
  [schema.NAME]     applied to an entry through its `_schema` field: a comma-separated list of
                    schema names. Every named schema applies (union of requirements).

Structural rules come from fixed XPath templates; they return a boolean or the
offending <String> elements, so only field *names* are reported. Value patterns
run in Python and report pass/fail only. No value is ever put in a result.
"""
from __future__ import annotations

import re
import tomllib
from collections import Counter
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Literal, NamedTuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import (
    LEVEL_ORDER,
    CompiledRule,
    Level,
    LinksReport,
    ReadReport,
    RuleCount,
    SchemaRules,
    SchemaView,
    UnclassifiedReport,
    ValidationReport,
    ValidationSummary,
)
from cprima_pdh_kdbxkit.kdbx_format import OTP_PREFIXES, STANDARD_ATTR

DEFAULT_PROFILE = "pdh-default"  # the profile whose [level] and [standard] a taxonomy fragment inherits
SCHEMA_PSEUDO = "schema-field"  # pseudo-schema name for findings about the binding field itself
_LOWER = "translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"


class SchemaError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# implemented = active in validation; proposed = documented in the taxonomy only, ignored by every check
Maturity = Literal["implemented", "proposed"]


class FieldType(_Strict):
    """A term of the global vocabulary, and a type that schemas can assign to fields.

    Globally, every entry field is checked against these terms: a key equal to the term's
    name, one of its `aliases` (flagged as "rename to NAME"), or matching `match` (a regex
    on the key name, for families like PINs/tokens). `protected` is fixed per term:
    true = must be protected, false = must not be, unset = not checked.
    `kind`, `family` and `status` are taxonomy metadata (see `pdh method show`).
    """

    description: str = ""
    kind: str | None = None  # one of the taxonomy's `[kind.*]`
    family: list[str] = []  # schema families this term mostly belongs to (documentation)
    status: Maturity = "implemented"
    aliases: list[str] = []  # exact, case-sensitive alternate spellings
    match: str | None = None  # regex searched in the field name
    pattern: str | None = None  # the value must match completely (name/aliases only)
    protected: bool | None = None
    generate: bool = False  # pdh may generate its value: a secret the owner makes up, never one issued by someone else
    example: str | None = None  # an obviously fake value for samples and docs; must fit `pattern`; else the kind's


class SchemaDef(_Strict):
    description: str = ""
    family: str | None = None  # taxonomy family of a record type (documentation)
    area: str | None = None  # the `[area.*]` where entries of this record type belong by default
    status: Maturity = "implemented"
    facets: list[str] = []
    required: list[str] = []  # MUST: a missing field is an ERROR
    recommended: list[str] = []  # SHOULD: a missing field is a WARN
    optional: list[str] = []  # MAY: allowed, never a finding
    protected: list[str] = []
    https_only: bool = False
    expires: bool = False
    closed: bool = False
    aliases: dict[str, list[str]] = {}
    types: dict[str, str] = {}  # field name -> [field.*] type name
    links: dict[str, list[str]] = {}  # link field (a term of kind `link`) -> schemas its target may have


class AreaDef(_Strict):
    description: str


class FamilyDef(_Strict):
    description: str


class KindDef(_Strict):
    description: str
    onepassword: str | None = None  # the 1Password field type this kind emulates
    default_protected: bool | None = None  # documentation: what protection this kind normally has
    behaviour: Literal["link"] | None = None  # the one thing the engine does with a kind: `link` = holds an entry reference
    example: str | None = None  # an obviously fake value for terms of this kind that have none of their own


class AxisDef(_Strict):
    name: str
    meaning: str
    where: str  # where the axis lives in the database
    status: Literal["decided", "implemented", "proposed", "open"]


class DecisionDef(_Strict):
    date: str  # YYYY-MM-DD
    status: Literal["decided", "open"]
    text: str
    by: str = ""


class SourceDef(_Strict):
    title: str
    url: str


class Levels(_Strict):
    """Severity of findings, by rule: an exact rule id (`schema:unknown`), else its kind (`required`), else `default`."""

    default: Level = "WARN"
    by_rule: dict[str, Level] = {}

    def of(self, rule_id: str) -> Level:
        if rule_id in self.by_rule:
            return self.by_rule[rule_id]
        return self.by_rule.get(rule_id.split(":")[0], self.default)


class StandardDef(_Strict):
    """A standard field every entry has (title, user name, password, ...). How the store keeps it is the backend's."""

    kind: str  # one of the taxonomy's `[kind.*]`
    description: str = ""
    generate: bool = False  # pdh may generate its value (the password of a login)
    example: str | None = None  # an obviously fake value; else the kind's


class AdviceDef(_Strict):
    """What to do about a finding. The key is a rule id (`required:URL`), a rule kind (`required`) or either with
    `@vocabulary` (a finding about a vocabulary term itself); `default` covers the rest.

    `command` is a template: `{entry}` is the quoted entry path, `{term}` the term after the colon of the rule id,
    `{field}` each field the finding names (the command is repeated per field, joined by ` ; `). `note` may use
    `{term}`; without a note the finding's own message is the note.
    """

    action: str
    automatable: bool = False  # True: an agent may run `command` without asking the owner
    command: str | None = None
    note: str | None = None


class BindingDef(_Strict):
    """How an entry names its record types: a custom field holding comma-separated record type names."""

    field: str = Field(min_length=1)


class MatchDef(_Strict):
    """A field-based rule: an entry that has every field in `has` (non-empty) is of record type `schema`.

    It works next to an explicit `_schema`: the types of an entry are the union of both.
    """

    schema_name: str = Field(alias="schema")
    has: list[str] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ProfileMeta(_Strict):
    """Identity of a profile: one complete variant of a taxonomy; a vault follows exactly one.

    `taxonomy` names the taxonomy (for example `pdh`), `name` the profile within it (`default`); together they are the
    full name `pdh-default`, by which the profile is selected (`--profile`), configured and filed (`pdh-default.toml`).
    """

    taxonomy: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    name: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    version: str
    description: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.taxonomy}-{self.name}"


class TaxonomyMeta(_Strict):
    title: str = "Taxonomy"
    purpose: str = ""
    principles: list[str] = []
    naming_rules: list[str] = []
    binding_rules: list[str] = []


class SchemaSet(BaseModel):
    """Active definitions drive validation; `proposed_*` and the taxonomy sections are documentation only."""

    fields: dict[str, FieldType]
    facets: dict[str, SchemaDef]
    schemas: dict[str, SchemaDef]
    proposed_fields: dict[str, FieldType] = {}
    proposed_schemas: dict[str, SchemaDef] = {}
    profile: ProfileMeta | None = None
    levels: Levels = Levels()
    standard: dict[str, StandardDef] = {}
    advice: dict[str, AdviceDef] = {}
    binding: BindingDef = BindingDef(field="binding")  # complete profiles state it; fragments inherit the default's
    matches: list[MatchDef] = []
    meta: TaxonomyMeta = TaxonomyMeta()
    areas: dict[str, AreaDef] = {}
    families: dict[str, FamilyDef] = {}
    kinds: dict[str, KindDef] = {}
    axes: list[AxisDef] = []
    decisions: list[DecisionDef] = []
    sources: list[SourceDef] = []

    def is_link(self, term: str) -> bool:
        """Whether a vocabulary term is of a kind that holds an entry reference (decided by the kind's `behaviour`)."""
        ft = self.fields.get(term) or self.proposed_fields.get(term)
        kind = self.kinds.get(ft.kind) if ft and ft.kind else None
        return bool(kind and kind.behaviour == "link")

    def example_of(self, term: str) -> str | None:
        """An obviously fake value for a vocabulary term: its own `example`, else its kind's."""
        ft = self.fields.get(term) or self.proposed_fields.get(term)
        if ft is None:
            return None
        return ft.example or (self.kinds[ft.kind].example if ft.kind in self.kinds else None)

    def example_of_standard(self, name: str) -> str | None:
        sd = self.standard.get(name)
        return None if sd is None else sd.example or self.kinds[sd.kind].example


_SECTIONS = {"profile", "level", "standard", "advice", "binding", "match", "field", "facet", "schema", "taxonomy", "area", "family", "kind",
             "axis", "decision", "source"}


@lru_cache(maxsize=1)
def _default_tables() -> dict:
    """The raw [level], [standard] and [kind] tables of the default profile: what a fragment that omits them gets.

    Complete profiles state all three themselves (a test enforces it); only fragments, such as the small taxonomies of
    unit tests, inherit. Read as plain TOML, so there is no recursion into the loader."""
    text = (files("cprima_pdh") / "data" / "profiles" / f"{DEFAULT_PROFILE}.toml").read_text(encoding="utf-8")
    raw = tomllib.loads(text)
    return {"level": raw["level"], "standard": raw["standard"], "kind": raw["kind"], "advice": raw["advice"],
            "binding": raw["binding"]}


def _levels(table: dict) -> Levels:
    table = dict(table)
    return Levels(default=table.pop("default", "WARN"), by_rule=table)


def parse_schemas(text: str, source: str = "<string>") -> SchemaSet:
    """Parse and validate a schema file given as TOML text (no file access; used by tests too)."""
    try:
        raw = tomllib.loads(text)
        unknown = set(raw) - _SECTIONS
        if unknown:
            raise SchemaError(f"unknown top-level section(s): {', '.join(sorted(unknown))}")
        fields = {n: FieldType(**b) for n, b in raw.get("field", {}).items()}
        schemas = {n: SchemaDef(**b) for n, b in raw.get("schema", {}).items()}
        sset = SchemaSet(
            fields={n: f for n, f in fields.items() if f.status == "implemented"},
            facets={n: SchemaDef(**b) for n, b in raw.get("facet", {}).items()},
            schemas={n: s for n, s in schemas.items() if s.status == "implemented"},
            proposed_fields={n: f for n, f in fields.items() if f.status == "proposed"},
            proposed_schemas={n: s for n, s in schemas.items() if s.status == "proposed"},
            profile=ProfileMeta(**raw["profile"]) if "profile" in raw else None,
            levels=_levels(raw["level"] if "level" in raw else _default_tables()["level"]),
            standard={n: StandardDef(**b) for n, b in (raw["standard"] if "standard" in raw
                                                       else _default_tables()["standard"]).items()},
            advice={n: AdviceDef(**b) for n, b in (raw["advice"] if "advice" in raw
                                                   else _default_tables()["advice"]).items()},
            binding=BindingDef(**(raw["binding"] if "binding" in raw else _default_tables()["binding"])),
            matches=[MatchDef(**m) for m in raw.get("match", [])],
            meta=TaxonomyMeta(**raw.get("taxonomy", {})),
            areas={n: AreaDef(**b) for n, b in raw.get("area", {}).items()},
            families={n: FamilyDef(**b) for n, b in raw.get("family", {}).items()},
            kinds={n: KindDef(**b) for n, b in (raw["kind"] if "kind" in raw else _default_tables()["kind"]).items()},
            axes=[AxisDef(**b) for b in raw.get("axis", [])],
            decisions=[DecisionDef(**b) for b in raw.get("decision", [])],
            sources=[SourceDef(**b) for b in raw.get("source", [])],
        )
    except (tomllib.TOMLDecodeError, ValidationError, TypeError) as exc:
        raise SchemaError(f"{source}: {exc}") from exc
    _check(sset)
    return sset


def load_schemas(path: Path) -> SchemaSet:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaError(f"{path}: {exc}") from exc
    return parse_schemas(text, str(path))


def _check(sset: SchemaSet) -> None:
    if "default" not in sset.advice:
        raise SchemaError("advice: a taxonomy that states [advice.*] needs [advice.default]")
    for n, ft in {**sset.fields, **sset.proposed_fields}.items():
        if ft.kind is not None and ft.kind not in sset.kinds:
            raise SchemaError(f"field.{n}: unknown kind {ft.kind!r}")
    for n, sd in sset.standard.items():
        if sd.kind not in sset.kinds:
            raise SchemaError(f"standard.{n}: unknown kind {sd.kind!r}")
    claimed: dict[str, str] = {}
    for n, ft in {**sset.fields, **sset.proposed_fields}.items():  # a proposal must not clash with a live term
        for attr in ("pattern", "match"):
            if getattr(ft, attr):
                try:
                    re.compile(getattr(ft, attr))
                except re.error as exc:
                    raise SchemaError(f"field.{n}: bad {attr}: {exc}") from exc
        if ft.pattern and ft.example and not re.fullmatch(ft.pattern, ft.example):
            raise SchemaError(f"field.{n}: the example does not fit the pattern")
        for name in [n, *ft.aliases]:
            if name in claimed and claimed[name] != n:
                raise SchemaError(f"field name {name!r} is claimed by both {claimed[name]!r} and {n!r}")
            claimed[name] = n
    for kind, table in (("facet", sset.facets), ("schema", sset.schemas)):
        for n, d in table.items():
            for u in d.facets:
                if u not in sset.facets:
                    raise SchemaError(f"{kind}.{n}: unknown facet {u!r}")
            for f, t in d.types.items():
                if t not in sset.fields:
                    raise SchemaError(f"{kind}.{n}: field {f!r} has unknown type {t!r}")
    for m in sset.matches:
        if m.schema_name not in sset.schemas:  # a proposed or unknown type could never be satisfied
            raise SchemaError(f"match rule for {m.schema_name!r}: not an active schema")
    for d in sset.schemas.values():
        resolve(d, sset.facets)  # detects cycles
    for kind_, table in (("facet", sset.facets), ("schema", {**sset.schemas, **sset.proposed_schemas})):
        for n, d in table.items():
            for fld, targets in d.links.items():
                if not sset.is_link(fld):
                    raise SchemaError(f"{kind_}.{n}: link field {fld!r} must be a vocabulary term of a kind "
                                      f"with behaviour 'link'")
                for t in targets:
                    if t not in sset.schemas:  # a proposed or unknown schema could never be satisfied
                        raise SchemaError(f"{kind_}.{n}: link {fld!r} targets {t!r}, which is not an active schema")
    for n, d in {**sset.schemas, **sset.proposed_schemas}.items():
        if d.family is not None and d.family not in sset.families:
            raise SchemaError(f"schema.{n}: unknown family {d.family!r}")
        if d.area is not None and d.area not in sset.areas:
            raise SchemaError(f"schema.{n}: unknown area {d.area!r}")
    for n, ft in {**sset.fields, **sset.proposed_fields}.items():
        for fam in ft.family:
            if fam not in sset.families:
                raise SchemaError(f"field.{n}: unknown family {fam!r}")


def _union(a: list[str], b: list[str]) -> list[str]:
    return a + [x for x in b if x not in a]


def _merge(a: SchemaDef, b: SchemaDef) -> SchemaDef:
    return SchemaDef(
        description=b.description or a.description,
        required=_union(a.required, b.required),
        recommended=_union(a.recommended, b.recommended),
        optional=_union(a.optional, b.optional),
        protected=_union(a.protected, b.protected),
        https_only=a.https_only or b.https_only,
        expires=a.expires or b.expires,
        closed=a.closed or b.closed,
        aliases={**a.aliases, **b.aliases},
        types={**a.types, **b.types},
        links={f: _union(a.links.get(f, []), b.links.get(f, [])) for f in dict.fromkeys([*a.links, *b.links])},
    )


def resolve(d: SchemaDef, subs: dict[str, SchemaDef], trail: tuple[str, ...] = ()) -> SchemaDef:
    """Flatten `facets`: facets first, own settings last (own types override)."""
    out = SchemaDef()
    for u in d.facets:
        if u in trail:
            raise SchemaError(f"cyclic facet reference: {' -> '.join(trail + (u,))}")
        out = _merge(out, resolve(subs[u], subs, trail + (u,)))
    return _merge(out, d.model_copy(update={"facets": []}))


def _q(s: str) -> str:
    if "'" not in s:
        return f"'{s}'"
    if '"' not in s:
        return f'"{s}"'
    raise SchemaError(f"cannot quote field name {s!r}")


def _has_value(key: str) -> str:
    return f"String[Key={_q(key)}]/Value[normalize-space()]"


def _effective_protected(d: SchemaDef, fields: dict[str, FieldType]) -> list[str]:
    typed = [f for f, t in d.types.items() if fields[t].protected]
    return _union(d.protected, typed)


def closed_rule(d: SchemaDef, sset: SchemaSet) -> CompiledRule:
    """Flags every field that is not standard, OTP, the binding field, or allowed by `d` (required/optional/typed/alias)."""
    alias_names = [a for alts in d.aliases.values() for a in alts]
    allowed = (
        set(sset.standard) | {sset.binding.field} | set(d.required) | set(d.recommended) | set(d.optional)
        | set(d.protected) | set(d.types) | set(d.links) | set(alias_names)
    )
    cond = " and ".join(
        [f"not(Key={_q(a)})" for a in sorted(allowed)] + [f"not(starts-with(Key, '{p}'))" for p in OTP_PREFIXES]
    )
    return CompiledRule(id="closed:unknown-field", level=sset.levels.of("closed:unknown-field"),
                        message="field not in schema", xpath=f"String[{cond}]")


def compile_rules(d: SchemaDef, sset: SchemaSet, include_closed: bool = True) -> list[CompiledRule]:
    """The structural rules of one (flattened) schema. Levels and standard fields come from the taxonomy `sset`."""
    rules: list[CompiledRule] = []

    def add(rule_id: str, message: str, xpath: str) -> None:
        rules.append(CompiledRule(id=rule_id, level=sset.levels.of(rule_id), message=message, xpath=xpath))

    for f in d.required:
        add(f"required:{f}", f"missing or empty field {f}", f"not({_has_value(f)})")
    for f in d.recommended:
        add(f"recommended:{f}", f"missing recommended field {f}", f"not({_has_value(f)})")
    for f in _effective_protected(d, sset.fields):
        add(f"protected:{f}", f"field {f} should be protected",
            f"String[Key={_q(f)}][Value[normalize-space() and not(@Protected='True')]]")
    if d.https_only:
        add("url:https", "URL is not https",
            f"String[Key='URL'][Value[normalize-space() and not(starts-with({_LOWER}, 'https://'))]]")
    if d.expires:
        add("expires", "no expiry date set", "not(Times/Expires='True')")
    for canon, alts in d.aliases.items():
        cond = " or ".join(f"Key={_q(a)}" for a in alts)
        add(f"alias:{canon}", f"rename to {canon}", f"String[{cond}]")
    if d.closed and include_closed:
        rules.append(closed_rule(d, sset))
    return rules


def pattern_checks(d: SchemaDef, fields: dict[str, FieldType]) -> list[tuple[str, str, re.Pattern[str]]]:
    """(field, type name, compiled pattern) for typed fields whose type has a pattern."""
    return [(f, t, re.compile(fields[t].pattern)) for f, t in d.types.items() if fields[t].pattern]


def describe(sset: SchemaSet) -> SchemaRules:
    views = {}
    for n, d in sset.schemas.items():
        flat = resolve(d, sset.facets)
        rules = compile_rules(flat, sset)
        rules += [
            CompiledRule(id=f"pattern:{f}", level=sset.levels.of("pattern"), message=f"value does not match type {t}",
                         xpath=f"(python) re.fullmatch({rx.pattern!r}, value)")
            for f, t, rx in pattern_checks(flat, sset.fields)
        ]
        views[n] = SchemaView(description=flat.description, facets=d.facets, rules=rules)
    vocabulary = {}
    for n, ft in sset.fields.items():
        bits = [f"protected={str(ft.protected).lower()}" if ft.protected is not None else "protection not checked"]
        if ft.aliases:
            bits.append("aliases: " + ", ".join(ft.aliases))
        if ft.match:
            bits.append(f"name matches /{ft.match}/")
        if ft.pattern:
            bits.append(f"value /{ft.pattern}/")
        vocabulary[n] = "; ".join(bits)
    return SchemaRules(schemas=views, vocabulary=vocabulary)


VOCABULARY = "vocabulary"  # pseudo-schema name for findings from the global vocabulary


def vocabulary_index(fields: dict[str, FieldType]):
    exact = {}
    for n, ft in fields.items():
        exact[n] = (n, ft)
        for a in ft.aliases:
            exact[a] = (n, ft)
    matchers = [(n, ft, re.compile(ft.match)) for n, ft in fields.items() if ft.match]
    return exact, matchers


def lookup_term(key: str, exact, matchers) -> tuple[str, FieldType, bool] | None:
    """(term name, term, matched by exact name/alias?) for a field key; exact beats `match`."""
    hit = exact.get(key)
    if hit is not None:
        return hit[0], hit[1], True
    return next(((n, ft, False) for n, ft, rx in matchers if rx.search(key)), None)


def _schema_fields(d: SchemaDef) -> set[str]:
    """Every field a (resolved) schema names; those are known even when they are not vocabulary terms."""
    return {*d.required, *d.recommended, *d.optional, *d.protected, *d.types, *d.links,
            *(a for alts in d.aliases.values() for a in alts)}


_REF = re.compile(r"^\{REF:[A-Z]@I:([0-9A-F]{32})\}$", re.IGNORECASE)
_UUID = re.compile(
    r"^(?:[0-9A-F]{32}|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})$", re.IGNORECASE
)


def uuid_key(value: object) -> str:
    """A UUID in KeePass's own form: 32 hex digits, upper case, no hyphens."""
    return str(value).replace("-", "").upper()


def parse_link(raw: str | None) -> str | None:
    """The target UUID of a link value, or None. Accepts a KeePass reference by UUID (`{REF:T@I:<32 hex>}`,
    any field code) or a bare UUID. A reference by title is not supported: titles repeat and change."""
    text = (raw or "").strip()
    m = _REF.match(text)
    if m:
        return m.group(1).upper()
    return uuid_key(text) if _UUID.match(text) else None


def make_ref(uuid: object) -> str:
    """The KeePass reference `{REF:T@I:<UUID>}`: clients that resolve references show the target's title."""
    return f"{{REF:T@I:{uuid_key(uuid)}}}"


_LINK_MESSAGES = {
    "invalid": "link is not a UUID or a KeePass reference by UUID",
    "dangling": "link target does not exist",
    "self": "an entry cannot link to itself",
    "wrong-schema": "link target does not have one of the allowed schemas",
    "target-unclassified": "link target has no schema yet",
}


def parse_schema_names(raw: str | None, known: set[str] | dict) -> tuple[list[str], list[str]]:
    """Split a `_schema` value into (known names, unknown names): comma-separated, trimmed, de-duplicated."""
    seen: list[str] = []
    for part in (raw or "").split(","):
        name = part.strip()
        if name and name not in seen:
            seen.append(name)
    return [n for n in seen if n in known], [n for n in seen if n not in known]


class Typing(NamedTuple):
    """How an entry got its record types. `explicit` come from its `_schema`, `by_fields` from the profile's match
    rules for types it did not name itself; `unknown` are `_schema` names the profile does not have."""

    explicit: list[str]
    by_fields: list[str]
    unknown: list[str]

    @property
    def names(self) -> list[str]:
        """Every record type that applies to the entry: the union, explicit ones first."""
        return [*self.explicit, *self.by_fields]


def present_fields(e, binding: str) -> set[str]:
    """Names of the fields an entry has with a value (standard and custom; never a value itself)."""
    out = {name for name, attr in STANDARD_ATTR.items() if getattr(e, attr, None)}
    out.update(k for k, v in (e.custom_properties or {}).items() if v and k != binding)
    return out


def typing_of(e, sset: SchemaSet) -> Typing:
    """`_schema` and/or the profile's field-based match rules: the entry's types are the union of both."""
    explicit, unknown = parse_schema_names(e.get_custom_property(sset.binding.field), sset.schemas)
    by_fields: list[str] = []
    if sset.matches:
        have = present_fields(e, sset.binding.field)
        for m in sset.matches:
            if m.schema_name not in explicit and m.schema_name not in by_fields and set(m.has) <= have:
                by_fields.append(m.schema_name)
    return Typing(explicit, by_fields, unknown)


def summarize(report: ValidationReport) -> ValidationSummary:
    """Collapse findings to one count per (schema, rule): the number of distinct entries."""
    distinct = {(f.schema_name, f.rule, f.level, f.entry) for f in report.findings}
    counts = Counter((s, r, lvl) for s, r, lvl, _ in distinct)
    rules = [RuleCount(schema_name=s, rule=r, level=lvl, entries=n) for (s, r, lvl), n in counts.items()]
    rules.sort(key=lambda c: (-LEVEL_ORDER[c.level], -c.entries, c.schema_name, c.rule))
    return ValidationSummary(schemas=report.schemas, unclassified_entries=report.unclassified_entries, rules=rules)


def filter_level(report: ValidationReport, minimum: str) -> ValidationReport:
    """The report without findings below `minimum` (a display filter, like a log threshold)."""
    keep = [f for f in report.findings if LEVEL_ORDER[f.level] >= LEVEL_ORDER[minimum]]
    return report.model_copy(update={"findings": keep})


def worst_level(report: ValidationReport) -> str | None:
    """The highest level among the findings, or None when there are none."""
    return max((f.level for f in report.findings), key=lambda lvl: LEVEL_ORDER[lvl], default=None)



# --- the public reports: over snapshots of any backend (the rules themselves live in validation.py) ---

def validate(source, sset: SchemaSet) -> ValidationReport:
    from .validation import validate_entries
    from cprima_pdh_vault.vault import as_vault

    return validate_entries(as_vault(source).entries(), sset)


def read(source, sset: SchemaSet, only: str | None = None) -> ReadReport:
    from .validation import read_entries
    from cprima_pdh_vault.vault import as_vault

    return read_entries(as_vault(source).entries(), sset, only)


def links_report(source, sset: SchemaSet) -> LinksReport:
    from .validation import links_for
    from cprima_pdh_vault.vault import as_vault

    return links_for(as_vault(source).entries(), sset)


def unclassified(source, sset: SchemaSet, list_entries: bool = False) -> UnclassifiedReport:
    from .validation import unclassified_for
    from cprima_pdh_vault.vault import as_vault

    return unclassified_for(as_vault(source).entries(), sset, list_entries)
