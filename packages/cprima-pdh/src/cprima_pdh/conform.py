"""Which entries conform to their schemas and which do not, with an action per issue.

Built for a coding agent that decides how to edit: every issue says what kind of change would fix it,
whether pdh can do it without the owner (`automatable`) and which command does it. Values are never read
into the report.
"""
from __future__ import annotations

from .models import LEVEL_ORDER, ConformanceReport, EntryConformance, Issue, RuleFinding
from .schema import VOCABULARY, SchemaSet, _bind, validate


def _q(text: str) -> str:
    return '"' + text.replace('"', '\\"') + '"'


def _issue(f: RuleFinding) -> Issue:
    kind, _, term = f.rule.partition(":")
    fields = f.fields or ([term] if term and kind in ("required", "recommended") else [])
    ref = _q(f.entry)
    action, auto, command, note = "review", False, None, f.message

    if kind in ("required", "recommended"):
        action, command = "supply-value", f'pdh edit set {ref} {term} <value> --apply'
        note = "ask the owner for the value; never invent one"
    elif kind == "alias":
        action, auto = "rename-field", True
        command = " ; ".join(f"pdh edit rename-field {ref} {old} {term} --apply" for old in fields)
        note = f"same concept, old spelling: rename to {term}"
    elif kind in ("protected", "unprotected"):
        action = "protect-field" if kind == "protected" else "unprotect-field"
        if f.schema_name == VOCABULARY:  # a vocabulary term has a fixed protection that `fix` applies everywhere
            auto, command = True, "pdh edit vocabulary --apply"
        else:
            note = "toggle protection in the client, or re-enter the value with `set ... - --overwrite --protect`"
    elif f.rule in ("closed:unknown-field", "unknown-field"):
        action = "decide-field"
        note = "rename each field to a vocabulary term (pdh edit rename-field), or remove it in the client"
    elif f.rule == "url:https":
        action = "review-url"
        note = "http:// is a valid URI; change it only if the site really offers https"
    elif f.rule == "expires":
        action = "set-expiry"
        note = "set the expiry date in the client; pdh does not write it"
    elif f.rule == "schema:unknown":
        action, command = "fix-schema", f"pdh edit set {ref} _schema <schema> --overwrite --apply"
        note = "name a schema from `pdh method schemas`, or drop the field"
    elif kind == "link":
        action, command = "fix-link", f"pdh edit link {ref} <target> --overwrite --apply"
        note = "point the link field at an entry with an allowed schema"
    elif kind == "pattern":
        action = "review-value"
        note = "format hint only; the owner is responsible for the value"

    return Issue(schema=f.schema_name, rule=f.rule, level=f.level, fields=fields, message=f.message,
                 action=action, automatable=auto, command=command, note=note)


def conformance(kp, sset: SchemaSet, status: str = "nonconform", only_schema: str | None = None,
                level: str = "INFO") -> ConformanceReport:
    """Every live entry as conform / nonconform / unclassified; `status` and `only_schema` filter the list only."""
    by_entry: dict[str, list[RuleFinding]] = {}
    for f in validate(kp, sset).findings:
        if LEVEL_ORDER[f.level] >= LEVEL_ORDER[level]:
            by_entry.setdefault(f.entry, []).append(f)

    counts = {"conform": 0, "nonconform": 0, "unclassified": 0}
    listed: list[EntryConformance] = []
    for e, path, names, _unknown in _bind(kp, sset):
        ref = f"{path}/{e.title}"
        issues = [_issue(f) for f in by_entry.get(ref, [])]
        state = "nonconform" if issues else ("conform" if names else "unclassified")
        counts[state] += 1
        if (status in ("all", state)) and (only_schema is None or only_schema in names):
            listed.append(EntryConformance(entry=ref, username=e.username or "", status=state, schemas=names,
                                           issues=issues))
    listed.sort(key=lambda x: x.entry)
    return ConformanceReport(**counts, entries=listed)
