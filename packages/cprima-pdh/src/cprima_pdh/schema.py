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
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Literal, get_args

from lxml import etree
from pydantic import BaseModel, ConfigDict, ValidationError

if TYPE_CHECKING:  # pykeepass is the optional `kdbx` extra; it is only needed to open a vault
    from pykeepass import PyKeePass

from .models import (
    LEVEL_ORDER,
    CompiledRule,
    Level,
    Link,
    LinksReport,
    ReadReport,
    RuleCount,
    RuleFinding,
    SchemaRules,
    SchemaStats,
    SchemaView,
    TypedEntry,
    UnclassifiedReport,
    ValidationReport,
    ValidationSummary,
)
from .source import _gpath, _in_bin

STANDARD_FIELDS = ("Title", "UserName", "Password", "URL", "Notes")
OTP_PREFIXES = ("TimeOtp-", "HmacOtp-")  # KeePass 2 OTP plugin fields; `otp` itself is allowed by name
SCHEMA_FIELD = "_schema"  # custom field on an entry: comma-separated schema names
SCHEMA_PSEUDO = "schema-field"  # pseudo-schema name for findings about the _schema field itself
_LOWER = "translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"


class SchemaError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


Kind = Literal["text", "secret", "key", "identifier", "card", "phone", "email", "address", "url", "date", "otp", "link"]
KINDS: tuple[str, ...] = get_args(Kind)
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
    kind: Kind | None = None
    family: list[str] = []  # schema families this term mostly belongs to (documentation)
    status: Maturity = "implemented"
    aliases: list[str] = []  # exact, case-sensitive alternate spellings
    match: str | None = None  # regex searched in the field name
    pattern: str | None = None  # the value must match completely (name/aliases only)
    protected: bool | None = None


class SchemaDef(_Strict):
    description: str = ""
    family: str | None = None  # taxonomy family of a record type (documentation)
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
    meta: TaxonomyMeta = TaxonomyMeta()
    areas: dict[str, AreaDef] = {}
    families: dict[str, FamilyDef] = {}
    kinds: dict[str, KindDef] = {}
    axes: list[AxisDef] = []
    decisions: list[DecisionDef] = []
    sources: list[SourceDef] = []


_SECTIONS = {"field", "facet", "schema", "taxonomy", "area", "family", "kind", "axis", "decision", "source"}


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
            meta=TaxonomyMeta(**raw.get("taxonomy", {})),
            areas={n: AreaDef(**b) for n, b in raw.get("area", {}).items()},
            families={n: FamilyDef(**b) for n, b in raw.get("family", {}).items()},
            kinds={n: KindDef(**b) for n, b in raw.get("kind", {}).items()},
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
    claimed: dict[str, str] = {}
    for n, ft in {**sset.fields, **sset.proposed_fields}.items():  # a proposal must not clash with a live term
        for attr in ("pattern", "match"):
            if getattr(ft, attr):
                try:
                    re.compile(getattr(ft, attr))
                except re.error as exc:
                    raise SchemaError(f"field.{n}: bad {attr}: {exc}") from exc
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
    for d in sset.schemas.values():
        resolve(d, sset.facets)  # detects cycles
    for kind_, table in (("facet", sset.facets), ("schema", {**sset.schemas, **sset.proposed_schemas})):
        for n, d in table.items():
            for fld, targets in d.links.items():
                term = sset.fields.get(fld) or sset.proposed_fields.get(fld)
                if term is None or term.kind != "link":
                    raise SchemaError(f"{kind_}.{n}: link field {fld!r} must be a vocabulary term of kind 'link'")
                for t in targets:
                    if t not in sset.schemas:  # a proposed or unknown schema could never be satisfied
                        raise SchemaError(f"{kind_}.{n}: link {fld!r} targets {t!r}, which is not an active schema")
    for n, d in {**sset.schemas, **sset.proposed_schemas}.items():
        if d.family is not None and d.family not in sset.families:
            raise SchemaError(f"schema.{n}: unknown family {d.family!r}")
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


def closed_rule(d: SchemaDef) -> CompiledRule:
    """Flags every field that is not standard, OTP, `_schema`, or allowed by `d` (required/optional/typed/alias)."""
    alias_names = [a for alts in d.aliases.values() for a in alts]
    allowed = (
        set(STANDARD_FIELDS) | {"otp", SCHEMA_FIELD} | set(d.required) | set(d.recommended) | set(d.optional)
        | set(d.protected) | set(d.types) | set(d.links) | set(alias_names)
    )
    cond = " and ".join(
        [f"not(Key={_q(a)})" for a in sorted(allowed)] + [f"not(starts-with(Key, '{p}'))" for p in OTP_PREFIXES]
    )
    return CompiledRule(id="closed:unknown-field", level=level_of("closed:unknown-field"),
                        message="field not in schema", xpath=f"String[{cond}]")


def level_of(rule_id: str) -> Level:
    """Default level of a rule: required / unknown schema = ERROR, pattern hints = INFO, everything else = WARN.

    `http://` is a valid URI, so `url:https` is only ever a WARN. Requirement tiers on the schema side map to
    levels: `required` (MUST) -> ERROR, `recommended` (SHOULD) -> WARN, `optional` (MAY) -> no finding.
    """
    kind = rule_id.split(":")[0]
    if kind == "required" or rule_id in ("schema:unknown", "link:invalid", "link:dangling", "link:self"):
        return "ERROR"
    if kind == "pattern" or rule_id == "link:target-unclassified":
        return "INFO"
    return "WARN"  # includes link:wrong-schema


def compile_rules(d: SchemaDef, fields: dict[str, FieldType], include_closed: bool = True) -> list[CompiledRule]:
    rules: list[CompiledRule] = []

    def add(rule_id: str, message: str, xpath: str) -> None:
        rules.append(CompiledRule(id=rule_id, level=level_of(rule_id), message=message, xpath=xpath))

    for f in d.required:
        add(f"required:{f}", f"missing or empty field {f}", f"not({_has_value(f)})")
    for f in d.recommended:
        add(f"recommended:{f}", f"missing recommended field {f}", f"not({_has_value(f)})")
    for f in _effective_protected(d, fields):
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
        rules.append(closed_rule(d))
    return rules


def pattern_checks(d: SchemaDef, fields: dict[str, FieldType]) -> list[tuple[str, str, re.Pattern[str]]]:
    """(field, type name, compiled pattern) for typed fields whose type has a pattern."""
    return [(f, t, re.compile(fields[t].pattern)) for f, t in d.types.items() if fields[t].pattern]


def describe(sset: SchemaSet) -> SchemaRules:
    views = {}
    for n, d in sset.schemas.items():
        flat = resolve(d, sset.facets)
        rules = compile_rules(flat, sset.fields)
        rules += [
            CompiledRule(id=f"pattern:{f}", level=level_of("pattern"), message=f"value does not match type {t}",
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
NOT_CUSTOM_PREFIXES = ("TimeOtp-", "HmacOtp-")


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


def _vocabulary_findings(e, ref: str, exact, matchers, skip: set[tuple[str, str, str]],
                         known: set[str] = frozenset()) -> list[RuleFinding]:
    """Findings per field; rule ids carry the vocabulary *term*, so summaries stay short.

    `skip` holds (entry, kind, field) triples the entry's schema already reported. `known` are the fields
    the entry's own schemas name. The taxonomy is dogma: with a vocabulary present, any other custom field
    name is unsupported and reported once per entry as `unknown-field` (WARN).
    """
    out: list[RuleFinding] = []
    unknown: list[str] = []

    def add(kind: str, term: str, message: str, key: str) -> None:
        if (ref, kind, key) not in skip:
            rule = f"{kind}:{term}"
            out.append(RuleFinding(schema=VOCABULARY, entry=ref, rule=rule, level=level_of(rule),
                                   message=message, fields=[key]))

    for key in (e.custom_properties or {}):
        if key.startswith(NOT_CUSTOM_PREFIXES):
            continue
        found = lookup_term(key, exact, matchers)
        if found is None:
            if (exact or matchers) and key != SCHEMA_FIELD and key not in known and (ref, "closed", key) not in skip:
                unknown.append(key)
            continue
        name, ft, by_name = found
        if key != name and key in ft.aliases:
            add("alias", name, f"rename to {name}", key)
        protected = bool(e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key))
        if ft.protected is True and not protected:
            add("protected", name, f"field {key} should be protected", key)
        elif ft.protected is False and protected:
            add("unprotected", name, f"field {key} should not be protected", key)
        if by_name and ft.pattern:
            value = e.get_custom_property(key) or ""  # compared in memory, never reported
            if value and not re.fullmatch(ft.pattern, value):
                add("pattern", name, f"value does not match type {name}", key)
    if unknown:
        out.append(RuleFinding(schema=VOCABULARY, entry=ref, rule="unknown-field", level=level_of("unknown-field"),
                               message="field name not in the vocabulary (unsupported)", fields=sorted(unknown)))
    return out


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


def _resolve_link(e, raw: str, targets: list[str], index: dict) -> tuple[str, str | None]:
    """(status, target as group/title or None) for one link value. Structure only; never reads what is linked."""
    key = parse_link(raw)
    if key is None:
        return "invalid", None
    hit = index.get(key)
    if key == uuid_key(e.uuid):
        return "self", (f"{hit[1]}/{hit[0].title}" if hit else None)
    if hit is None:
        return "dangling", None
    target, path, names = hit
    ref = f"{path}/{target.title}"
    if not names:
        return "target-unclassified", ref
    if not set(names) & set(targets):
        return "wrong-schema", ref
    return "ok", ref


def _link_findings(e, ref: str, names: list[str], flat: dict[str, SchemaDef], index: dict) -> list[RuleFinding]:
    """Findings for the link fields of the schemas an entry names. An absent field is a `required` question."""
    out: list[RuleFinding] = []
    for n in names:
        for fld, targets in flat[n].links.items():
            raw = e.get_custom_property(fld)
            if not raw or not raw.strip():
                continue
            status, _target = _resolve_link(e, raw, targets, index)
            if status != "ok":
                rule = f"link:{status}"
                out.append(RuleFinding(schema=n, entry=ref, rule=rule, level=level_of(rule),
                                       message=_LINK_MESSAGES[status], fields=[fld]))
    return out


def parse_schema_names(raw: str | None, known: set[str] | dict) -> tuple[list[str], list[str]]:
    """Split a `_schema` value into (known names, unknown names): comma-separated, trimmed, de-duplicated."""
    seen: list[str] = []
    for part in (raw or "").split(","):
        name = part.strip()
        if name and name not in seen:
            seen.append(name)
    return [n for n in seen if n in known], [n for n in seen if n not in known]


def _bind(kp: PyKeePass, sset: SchemaSet) -> Iterator[tuple[object, str, list[str], list[str]]]:
    """Yield (entry, group path, known schema names, unknown names) for every live entry."""
    rb = kp.recyclebin_group
    bin_uuid = rb.uuid if rb is not None else None
    for e in kp.entries:
        if bin_uuid is not None and _in_bin(e.group, bin_uuid):
            continue
        names, unknown = parse_schema_names(e.get_custom_property(SCHEMA_FIELD), sset.schemas)
        yield e, _gpath(e.group), names, unknown


_STANDARD_ATTR = {"Title": "title", "UserName": "username", "Password": "password", "URL": "url", "Notes": "notes"}


def _value(e, key: str) -> str:
    if key in _STANDARD_ATTR:
        return getattr(e, _STANDARD_ATTR[key]) or ""
    return e.get_custom_property(key) or ""


def _is_protected(e, key: str, schema_protected: list[str]) -> bool:
    return (
        key == "Password"
        or key in schema_protected
        or bool(e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key))
    )


def _combined_findings(
    e, ref: str, names: list[str], flat: dict[str, SchemaDef], closed_xp: dict[tuple[str, ...], tuple]
) -> list[RuleFinding]:
    """Findings that only exist when several schemas apply together: `closed` over the union, type conflicts."""
    label = "+".join(names)
    out: list[RuleFinding] = []
    applied = [flat[n] for n in names]
    if any(d.closed for d in applied):
        key = tuple(names)
        if key not in closed_xp:
            merged = applied[0]
            for d in applied[1:]:
                merged = _merge(merged, d)
            rule = closed_rule(merged)
            closed_xp[key] = (rule, etree.XPath(rule.xpath))
        rule, xp = closed_xp[key]
        hits = [x.findtext("Key") or "" for x in xp(e._element)]
        if hits:
            out.append(RuleFinding(schema=label, entry=ref, rule=rule.id, level=rule.level,
                                   message=rule.message, fields=hits))
    if len(names) > 1:
        typed: dict[str, set[str]] = {}
        for d in applied:
            for field, t in d.types.items():
                typed.setdefault(field, set()).add(t)
        for field, ts in sorted(typed.items()):
            if len(ts) > 1:
                out.append(RuleFinding(schema=label, entry=ref, rule="schema:type-conflict", level="WARN",
                                       message=f"schemas type this field differently ({', '.join(sorted(ts))})",
                                       fields=[field]))
    return out


def validate(kp: PyKeePass, sset: SchemaSet) -> ValidationReport:
    flat = {n: resolve(d, sset.facets) for n, d in sset.schemas.items()}
    xpaths = {
        n: [(r, etree.XPath(r.xpath)) for r in compile_rules(d, sset.fields, include_closed=False)]
        for n, d in flat.items()
    }
    patterns = {n: pattern_checks(d, sset.fields) for n, d in flat.items()}
    closed_xp: dict[tuple[str, ...], tuple] = {}

    exact, matchers = vocabulary_index(sset.fields)
    counts = {n: [0, 0] for n in flat}  # entries naming the schema, conforming
    vocab = [0, 0]
    findings: list[RuleFinding] = []
    unclassified = 0
    bound = list(_bind(kp, sset))
    index = {uuid_key(e.uuid): (e, path, names) for e, path, names, _u in bound}  # live entries by UUID
    for e, path, names, unknown in bound:
        ref = f"{path}/{e.title}"
        first = len(findings)
        for u in unknown:
            findings.append(RuleFinding(schema=SCHEMA_PSEUDO, entry=ref, rule="schema:unknown", level="ERROR",
                                        message=f"unknown schema name in {SCHEMA_FIELD}", fields=[u]))
        if not names:
            unclassified += 1
        else:
            hits = {n: _check_schema(e, ref, n, xpaths, patterns, findings) for n in names}
            combined = _combined_findings(e, ref, names, flat, closed_xp) + _link_findings(e, ref, names, flat, index)
            findings += combined
            for n in names:
                counts[n][0] += 1
                counts[n][1] += hits[n] == 0 and not combined
        # the same finding reported by several schemas is listed once
        deduped, seen_keys = [], set()
        for f in findings[first:]:
            key = (f.rule, tuple(f.fields))
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)
        findings[first:] = deduped
        # vocabulary applies to every entry; skip what the entry's schemas already reported
        seen = {(ref, f.rule.split(":")[0], k) for f in findings[first:] for k in f.fields}
        known = set().union(*(_schema_fields(flat[n]) for n in names)) if names else set()
        vf = _vocabulary_findings(e, ref, exact, matchers, seen, known)
        findings += vf
        vocab[0] += 1
        vocab[1] += not vf

    findings.sort(key=lambda f: (f.schema_name, f.entry, f.rule))
    stats = {n: SchemaStats(entries=c[0], conforming=c[1], with_findings=c[0] - c[1]) for n, c in counts.items()}
    if exact or matchers:
        stats[VOCABULARY] = SchemaStats(entries=vocab[0], conforming=vocab[1], with_findings=vocab[0] - vocab[1])
    return ValidationReport(schemas=stats, unclassified_entries=unclassified, findings=findings)


def _check_schema(e, ref, name, xpaths, patterns, findings) -> int:
    """Run one entry through one schema's XPath rules and value patterns; returns the number of hits."""
    hits = 0
    for rule, xp in xpaths[name]:
        res = xp(e._element)
        if isinstance(res, bool):
            hit, fields = res, []
        else:
            hit, fields = bool(res), [x.findtext("Key") or "" for x in res]
        if hit:
            hits += 1
            findings.append(RuleFinding(schema=name, entry=ref, rule=rule.id, level=rule.level,
                                        message=rule.message, fields=fields))
    for field, type_name, rx in patterns[name]:
        value = _value(e, field)  # compared in memory, never reported
        if value and not rx.fullmatch(value):
            hits += 1
            findings.append(RuleFinding(schema=name, entry=ref, rule=f"pattern:{field}", level=level_of("pattern"),
                                        message=f"value does not match type {type_name}", fields=[field]))
    return hits


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


def read(kp: PyKeePass, sset: SchemaSet, only: str | None = None) -> ReadReport:
    """Entries as typed records of their schema's fields; protected values are not read."""
    flat = {n: resolve(d, sset.facets) for n, d in sset.schemas.items()}
    out: list[TypedEntry] = []
    unclassified = 0
    for e, path, names, _unknown in _bind(kp, sset):
        if not names:
            unclassified += 1
            continue
        for name in names:  # one typed record per schema the entry names
            if only and name != only:
                continue
            d = flat[name]
            protected = _effective_protected(d, sset.fields)
            values: dict[str, str] = {}
            keys = _union(_union(_union(_union(d.required, d.recommended), d.optional), d.protected), list(d.types))
            for key in _union(keys, list(d.links)):
                if _is_protected(e, key, protected):
                    if _value(e, key):
                        values[key] = "(protected)"
                elif v := _value(e, key):
                    values[key] = v
            out.append(TypedEntry(schema=name, entry=f"{path}/{e.title}", fields=values))
    out.sort(key=lambda t: (t.schema_name, t.entry))
    return ReadReport(entries=out, unclassified_entries=unclassified)


def links_report(kp: PyKeePass, sset: SchemaSet) -> LinksReport:
    """Every link of every typed entry with its status, and how many links each target receives."""
    flat = {n: resolve(d, sset.facets) for n, d in sset.schemas.items()}
    bound = list(_bind(kp, sset))
    index = {uuid_key(e.uuid): (e, path, names) for e, path, names, _u in bound}
    seen: dict[tuple[str, str], Link] = {}
    for e, path, names, _unknown in bound:
        for n in names:
            for fld, targets in flat[n].links.items():
                raw = e.get_custom_property(fld)
                if not raw or not raw.strip() or (f"{path}/{e.title}", fld) in seen:
                    continue
                status, target = _resolve_link(e, raw, targets, index)
                source = f"{path}/{e.title}"
                seen[(source, fld)] = Link(source=source, field=fld, target=target, status=status)
    links = sorted(seen.values(), key=lambda lk: (lk.source, lk.field))
    per_target = Counter(lk.target for lk in links if lk.target and lk.status != "self")
    return LinksReport(links=links, per_target=dict(per_target))


def unclassified(kp: PyKeePass, sset: SchemaSet, list_entries: bool = False) -> UnclassifiedReport:
    """Live entries without a valid `_schema`: the seeding to-do list."""
    per_group: Counter[str] = Counter()
    refs: list[str] = []
    for e, path, names, _unknown in _bind(kp, sset):
        if names:
            continue
        per_group[path] += 1
        if list_entries:
            refs.append(f"{path}/{e.title}")
    return UnclassifiedReport(total=sum(per_group.values()), per_group=dict(per_group), entries=sorted(refs))
