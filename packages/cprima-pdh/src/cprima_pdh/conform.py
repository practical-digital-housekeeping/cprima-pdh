"""Which entries conform to their schemas and which do not, with an action per issue.

Built for a coding agent that decides how to edit: every issue says what kind of change would fix it,
whether pdh can do it without the owner (`automatable`) and which command does it. Values are never read
into the report.
"""
from __future__ import annotations

from .models import LEVEL_ORDER, ConformanceReport, EntryConformance, Issue, RuleFinding
from .schema import VOCABULARY, SchemaSet
from .validation import live, typing_of, validate_entries
from .vault import as_vault


def _q(text: str) -> str:
    return '"' + text.replace('"', '\\"') + '"'


def _advice(f: RuleFinding, sset: SchemaSet):
    """The profile's advice for a finding: the most specific key wins (exact rule id, then its kind, then `default`);
    a finding about a vocabulary term itself prefers the `@vocabulary` variant of each."""
    kind = f.rule.partition(":")[0]
    scoped = ["@vocabulary", ""] if f.schema_name == VOCABULARY else [""]
    for key in (f.rule, kind):
        for scope in scoped:
            if key + scope in sset.advice:
                return sset.advice[key + scope]
    return sset.advice["default"]


def _issue(f: RuleFinding, sset: SchemaSet) -> Issue:
    term = f.rule.partition(":")[2]
    fields = f.fields or ([term] if term else [])
    advice = _advice(f, sset)
    ref = _q(f.entry)

    def fill(text: str, field: str = "") -> str:
        return (text.replace("{entry}", ref).replace("{term}", term).replace("{field}", field)
                .replace("{binding}", sset.binding.field))

    command = None
    if advice.command:
        command = (" ; ".join(fill(advice.command, x) for x in fields)
                   if "{field}" in advice.command else fill(advice.command))
    note = fill(advice.note) if advice.note else f.message
    return Issue(schema=f.schema_name, rule=f.rule, level=f.level, fields=fields, message=f.message,
                 action=advice.action, automatable=advice.automatable, command=command, note=note)


def conformance(kp, sset: SchemaSet, status: str = "nonconform", only_schema: str | None = None,
                level: str = "INFO") -> ConformanceReport:
    """Every live entry as conform / nonconform / unclassified; `status` and `only_schema` filter the list only."""
    entries = as_vault(kp).entries()  # one snapshot for the whole report
    by_entry: dict[str, list[RuleFinding]] = {}
    for f in validate_entries(entries, sset).findings:
        if LEVEL_ORDER[f.level] >= LEVEL_ORDER[level]:
            by_entry.setdefault(f.entry, []).append(f)

    counts = {"conform": 0, "nonconform": 0, "unclassified": 0}
    listed: list[EntryConformance] = []
    for e in live(entries):
        names, ref = typing_of(e, sset).names, e.path
        issues = [_issue(f, sset) for f in by_entry.get(ref, [])]
        state = "nonconform" if issues else ("conform" if names else "unclassified")
        counts[state] += 1
        if (status in ("all", state)) and (only_schema is None or only_schema in names):
            listed.append(EntryConformance(entry=ref, username=e.username or "", status=state, schemas=names,
                                           issues=issues))
    listed.sort(key=lambda x: x.entry)
    return ConformanceReport(**counts, entries=listed)
