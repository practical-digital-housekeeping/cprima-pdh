"""Validation over snapshots: the schema and vocabulary checks of `schema.validate`, as plain Python over `EntryData`.

The profile's rules used to be compiled to XPath and run on an entry's raw XML. Here each rule is a small predicate over
the snapshot a backend hands out, so any backend can be validated and no engine code touches a store's own objects. The
results are identical to the XPath engine's (a parity test compares them on every fixture) until that engine is removed.
Values are compared in memory and never reported.
"""
from __future__ import annotations

import re

from .backends.kdbx import OTP_PREFIXES  # (the KeePass 2 OTP plugin's own fields are not user fields; moves to the backend)
from .models import RuleFinding, SchemaStats, ValidationReport
from .schema import (
    SCHEMA_PSEUDO,
    VOCABULARY,
    Levels,
    SchemaDef,
    SchemaSet,
    _effective_protected,
    _LINK_MESSAGES,
    _merge,
    _schema_fields,
    lookup_term,
    parse_link,
    parse_schema_names,
    pattern_checks,
    resolve,
    uuid_key,
    vocabulary_index,
    Typing,
)
from .vault import STANDARD, EntryData

_XML_SPACE = " \t\r\n"  # what XPath's normalize-space() treats as white space
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def field_value(e: EntryData, name: str) -> str:
    """The value of a standard or custom field ("" when the entry has no such field)."""
    if name in STANDARD:
        return e.value(name)
    return e.fields[name].value if name in e.fields else ""


def has_value(e: EntryData, name: str) -> bool:
    return bool(field_value(e, name).strip(_XML_SPACE))


# --- typing ----------------------------------------------------------------------------------------------------------------

def present_fields(e: EntryData, binding: str) -> set[str]:
    """Names of the fields an entry has with a value (standard and custom; never a value itself)."""
    out = {n for n in STANDARD if e.value(n)}
    out.update(k for k, f in e.fields.items() if f.value and k != binding)
    return out


def typing_of(e: EntryData, sset: SchemaSet) -> Typing:
    """The binding field and/or the profile's field-based match rules: the entry's types are the union of both."""
    raw = e.fields[sset.binding.field].value if sset.binding.field in e.fields else None
    explicit, unknown = parse_schema_names(raw, sset.schemas)
    by_fields: list[str] = []
    if sset.matches:
        have = present_fields(e, sset.binding.field)
        for m in sset.matches:
            if m.schema_name not in explicit and m.schema_name not in by_fields and set(m.has) <= have:
                by_fields.append(m.schema_name)
    return Typing(explicit, by_fields, unknown)


def live(entries: list[EntryData]) -> list[EntryData]:
    return [e for e in entries if not e.in_bin]


# --- one schema's rules ------------------------------------------------------------------------------------------------------

def _closed_allowed(d: SchemaDef, sset: SchemaSet) -> set[str]:
    alias_names = [a for alts in d.aliases.values() for a in alts]
    return (set(sset.standard) | {sset.binding.field} | set(d.required) | set(d.recommended) | set(d.optional)
            | set(d.protected) | set(d.types) | set(d.links) | set(alias_names))


def _closed_hits(e: EntryData, d: SchemaDef, sset: SchemaSet) -> list[str]:
    allowed = _closed_allowed(d, sset)
    return [k for k in e.fields if k not in allowed and not k.startswith(OTP_PREFIXES)]


def _schema_findings(e: EntryData, ref: str, name: str, d: SchemaDef, sset: SchemaSet) -> list[RuleFinding]:
    """The structural rules (in the order the XPath engine evaluated them) and the value patterns of one schema."""
    levels = sset.levels
    out: list[RuleFinding] = []

    def hit(rule_id: str, message: str, fields: list[str] | None = None) -> None:
        out.append(RuleFinding(schema=name, entry=ref, rule=rule_id, level=levels.of(rule_id), message=message,
                               fields=fields or []))

    for f in d.required:
        if not has_value(e, f):
            hit(f"required:{f}", f"missing or empty field {f}")
    for f in d.recommended:
        if not has_value(e, f):
            hit(f"recommended:{f}", f"missing recommended field {f}")
    for f in _effective_protected(d, sset.fields):
        if has_value(e, f) and not e.is_protected(f):
            hit(f"protected:{f}", f"field {f} should be protected", [f])
    if d.https_only:
        url = e.url
        if url.strip(_XML_SPACE) and not url.translate(_ASCII_LOWER).startswith("https://"):
            hit("url:https", "URL is not https", ["URL"])
    if d.expires and not e.expires:
        hit("expires", "no expiry date set")
    for canon, alts in d.aliases.items():
        found = [k for k in e.fields if k in alts]
        if found:
            hit(f"alias:{canon}", f"rename to {canon}", found)
    for field, type_name, rx in pattern_checks(d, sset.fields):
        value = field_value(e, field)
        if value and not rx.fullmatch(value):
            hit(f"pattern:{field}", f"value does not match type {type_name}", [field])
    return out


def _combined_findings(e: EntryData, ref: str, names: list[str], flat: dict[str, SchemaDef],
                       sset: SchemaSet) -> list[RuleFinding]:
    """Findings that only exist when several schemas apply together: `closed` over the union, type conflicts."""
    label = "+".join(names)
    out: list[RuleFinding] = []
    applied = [flat[n] for n in names]
    if any(d.closed for d in applied):
        merged = applied[0]
        for d in applied[1:]:
            merged = _merge(merged, d)
        hits = _closed_hits(e, merged, sset)
        if hits:
            out.append(RuleFinding(schema=label, entry=ref, rule="closed:unknown-field",
                                   level=sset.levels.of("closed:unknown-field"), message="field not in schema",
                                   fields=hits))
    if len(names) > 1:
        typed: dict[str, set[str]] = {}
        for d in applied:
            for field, t in d.types.items():
                typed.setdefault(field, set()).add(t)
        for field, ts in sorted(typed.items()):
            if len(ts) > 1:
                out.append(RuleFinding(schema=label, entry=ref, rule="schema:type-conflict",
                                       level=sset.levels.of("schema:type-conflict"),
                                       message=f"schemas type this field differently ({', '.join(sorted(ts))})",
                                       fields=[field]))
    return out


# --- links ---------------------------------------------------------------------------------------------------------------------

def _resolve_link(e: EntryData, raw: str, targets: list[str], index: dict) -> tuple[str, str | None]:
    """(status, target as group/title or None) for one link value. Structure only; never reads what is linked."""
    key = parse_link(raw)
    if key is None:
        return "invalid", None
    hit = index.get(key)
    if key == uuid_key(e.id):
        return "self", (hit[0].path if hit else None)
    if hit is None:
        return "dangling", None
    target, names = hit
    if not names:
        return "target-unclassified", target.path
    if not set(names) & set(targets):
        return "wrong-schema", target.path
    return "ok", target.path


def _link_findings(e: EntryData, ref: str, names: list[str], flat: dict[str, SchemaDef], index: dict,
                   levels: Levels) -> list[RuleFinding]:
    out: list[RuleFinding] = []
    for n in names:
        for fld, targets in flat[n].links.items():
            raw = e.fields[fld].value if fld in e.fields else ""
            if not raw or not raw.strip():
                continue
            status, _target = _resolve_link(e, raw, targets, index)
            if status != "ok":
                rule = f"link:{status}"
                out.append(RuleFinding(schema=n, entry=ref, rule=rule, level=levels.of(rule),
                                       message=_LINK_MESSAGES[status], fields=[fld]))
    return out


# --- the vocabulary ------------------------------------------------------------------------------------------------------------

def _vocabulary_findings(e: EntryData, ref: str, exact, matchers, skip: set[tuple[str, str, str]], levels: Levels,
                         known: set[str], binding: str) -> list[RuleFinding]:
    out: list[RuleFinding] = []
    unknown: list[str] = []

    def add(kind: str, term: str, message: str, key: str) -> None:
        if (ref, kind, key) not in skip:
            rule = f"{kind}:{term}"
            out.append(RuleFinding(schema=VOCABULARY, entry=ref, rule=rule, level=levels.of(rule), message=message,
                                   fields=[key]))

    for key, fld in e.fields.items():
        if key.startswith(OTP_PREFIXES):
            continue
        found = lookup_term(key, exact, matchers)
        if found is None:
            if (exact or matchers) and key != binding and key not in known and (ref, "closed", key) not in skip:
                unknown.append(key)
            continue
        name, ft, by_name = found
        if key != name and key in ft.aliases:
            add("alias", name, f"rename to {name}", key)
        if ft.protected is True and not fld.protected:
            add("protected", name, f"field {key} should be protected", key)
        elif ft.protected is False and fld.protected:
            add("unprotected", name, f"field {key} should not be protected", key)
        if by_name and ft.pattern and fld.value and not re.fullmatch(ft.pattern, fld.value):
            add("pattern", name, f"value does not match type {name}", key)
    if unknown:
        out.append(RuleFinding(schema=VOCABULARY, entry=ref, rule="unknown-field", level=levels.of("unknown-field"),
                               message="field name not in the vocabulary (unsupported)", fields=sorted(unknown)))
    return out


# --- the report -------------------------------------------------------------------------------------------------------------------

def validate_entries(entries: list[EntryData], sset: SchemaSet) -> ValidationReport:
    """Check every live entry against its record types and the vocabulary (same result as `schema.validate`)."""
    flat = {n: resolve(d, sset.facets) for n, d in sset.schemas.items()}
    levels = sset.levels
    exact, matchers = vocabulary_index(sset.fields)
    counts = {n: [0, 0] for n in flat}  # entries naming the schema, conforming
    vocab = [0, 0]
    findings: list[RuleFinding] = []
    unclassified = 0
    bound = [(e, typing_of(e, sset)) for e in live(entries)]
    index = {uuid_key(e.id): (e, t.names) for e, t in bound}  # live entries by UUID
    for e, typing in bound:
        ref, names = e.path, typing.names
        first = len(findings)
        for u in typing.unknown:
            findings.append(RuleFinding(schema=SCHEMA_PSEUDO, entry=ref, rule="schema:unknown",
                                        level=levels.of("schema:unknown"),
                                        message=f"unknown schema name in {sset.binding.field}", fields=[u]))
        if not names:
            unclassified += 1
        else:
            hits = {}
            for n in names:
                found = _schema_findings(e, ref, n, flat[n], sset)
                findings += found
                hits[n] = len(found)
            combined = _combined_findings(e, ref, names, flat, sset) + _link_findings(e, ref, names, flat, index, levels)
            findings += combined
            for n in names:
                counts[n][0] += 1
                counts[n][1] += hits[n] == 0 and not combined
        deduped, seen_keys = [], set()  # the same finding reported by several schemas is listed once
        for f in findings[first:]:
            key = (f.rule, tuple(f.fields))
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)
        findings[first:] = deduped
        seen = {(ref, f.rule.split(":")[0], k) for f in findings[first:] for k in f.fields}
        known = set().union(*(_schema_fields(flat[n]) for n in names)) if names else set()
        vf = _vocabulary_findings(e, ref, exact, matchers, seen, levels, known, sset.binding.field)
        findings += vf
        vocab[0] += 1
        vocab[1] += not vf

    findings.sort(key=lambda f: (f.schema_name, f.entry, f.rule))
    stats = {n: SchemaStats(entries=c[0], conforming=c[1], with_findings=c[0] - c[1]) for n, c in counts.items()}
    if exact or matchers:
        stats[VOCABULARY] = SchemaStats(entries=vocab[0], conforming=vocab[1], with_findings=vocab[0] - vocab[1])
    return ValidationReport(schemas=stats, unclassified_entries=unclassified, findings=findings)
