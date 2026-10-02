"""Renders the taxonomy document from schemas.toml (the single source of truth). Pure function, no I/O."""
from __future__ import annotations

from .models import TaxonomyDoc
from .schema import KINDS, FieldType, SchemaDef, SchemaSet, resolve


def _cell(value: object) -> str:
    text = " ".join(str(value).split()) if value not in (None, "") else "—"
    return text.replace("|", "\\|")


def _code(items: list[str]) -> str:
    return ", ".join(f"`{i}`" for i in items) if items else "—"


def _table(header: list[str], rows: list[list[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(_cell(c) if not str(c).startswith("`") else str(c).replace("|", "\\|") for c in r) + " |"
            for r in rows]
    return out


def _protection(ft: FieldType) -> str:
    return {True: "must be protected", False: "must not be protected", None: "not checked"}[ft.protected]


def _links(d: SchemaDef) -> str:
    return "; ".join(f"`{f}` → {_code(targets)}" for f, targets in d.links.items()) or "—"


def _flags(d: SchemaDef) -> str:
    return ", ".join(f for f, on in (("closed", d.closed), ("expires", d.expires), ("https_only", d.https_only)) if on) or "—"


def build(sset: SchemaSet) -> TaxonomyDoc:
    m = sset.meta
    out: list[str] = [
        f"# {m.title}",
        "",
        "> Generated from `schemas.toml` by `pdh method show`. Do not edit by hand: change `schemas.toml`, then run `just taxonomy`.",
        "",
    ]
    if m.purpose:
        out += [m.purpose.strip(), ""]

    def bullets(title: str, items: list[str]) -> None:
        if items:
            out.extend([f"## {title}", ""] + [f"- {i}" for i in items] + [""])

    bullets("Principles", m.principles)

    if sset.axes:
        out += ["## Axes", ""]
        out += _table(["Axis", "Meaning", "Where it lives", "Status"],
                      [[a.name, a.meaning, a.where, a.status] for a in sset.axes]) + [""]

    bullets("Naming rules", m.naming_rules)
    bullets("Binding rules (`_schema`)", m.binding_rules)

    if sset.areas:
        out += ["## Areas", ""]
        out += _table(["Area", "Meaning"], [[n, a.description] for n, a in sset.areas.items()]) + [""]

    # --- record types by family
    all_schemas = {**{n: (s, "implemented") for n, s in sset.schemas.items()},
                   **{n: (s, "proposed") for n, s in sset.proposed_schemas.items()}}
    out += ["## Record types (schemas)", ""]
    for fam, fdef in sset.families.items():
        members = {n: v for n, v in all_schemas.items() if v[0].family == fam}
        if not members:
            continue
        out += [f"### {fam}", "", fdef.description, ""]
        flats = {n: resolve(d, sset.facets) for n, (d, _status) in members.items()}
        rec = any(f.recommended for f in flats.values())  # a Recommended column only where it is used
        lnk = any(f.links for f in flats.values())  # likewise a Links column
        rows = [
            [f"`{n}`", status, d.description, _code(flats[n].required)]
            + ([_code(flats[n].recommended)] if rec else [])
            + [_code(flats[n].optional)]
            + ([_links(flats[n])] if lnk else [])
            + [_flags(flats[n])]
            for n, (d, status) in members.items()
        ]
        header = (["Schema", "Status", "Description", "Required"] + (["Recommended"] if rec else []) + ["Optional"]
                  + (["Links"] if lnk else []) + ["Flags"])
        out += _table(header, rows) + [""]
    loose = {n: v for n, v in all_schemas.items() if v[0].family is None}
    if loose:
        out += ["### (no family)", ""]
        out += _table(["Schema", "Status", "Description"], [[f"`{n}`", s, d.description] for n, (d, s) in loose.items()]) + [""]

    # --- facets
    if sset.facets:
        out += ["## Facets (reusable bundles)", ""]
        flats = {n: resolve(d, sset.facets) for n, d in sset.facets.items()}
        rec = any(f.recommended for f in flats.values())
        rows = [
            [f"`{n}`", d.description, _code(flats[n].required)]
            + ([_code(flats[n].recommended)] if rec else [])
            + [_code(flats[n].optional), _flags(flats[n])]
            for n, d in sset.facets.items()
        ]
        header = ["Facet", "Description", "Required"] + (["Recommended"] if rec else []) + ["Optional", "Flags"]
        out += _table(header, rows) + [""]

    # --- kinds and vocabulary
    if sset.kinds:
        out += ["## Field kinds", ""]
        out += _table(["Kind", "Meaning", "1Password type", "Normal protection"],
                      [[f"`{k}`", sset.kinds[k].description, sset.kinds[k].onepassword,
                        {True: "protected", False: "not protected", None: "—"}[sset.kinds[k].default_protected]]
                       for k in KINDS if k in sset.kinds]) + [""]

    terms = {**{n: (t, "implemented") for n, t in sset.fields.items()},
             **{n: (t, "proposed") for n, t in sset.proposed_fields.items()}}
    out += ["## Field vocabulary", ""]
    for kind in [*KINDS, None]:
        members = {n: v for n, v in terms.items() if v[0].kind == kind}
        if not members:
            continue
        out += [f"### {kind or '(no kind)'}", ""]
        rows = []
        for n, (t, status) in members.items():
            desc = t.description + (" Recognised by a name pattern." if t.match else "")
            rows.append([f"`{n}`", status, desc.strip(), _code(t.aliases), _protection(t),
                         f"`{t.pattern}`" if t.pattern else "—", _code(t.family)])
        out += _table(["Term", "Status", "Description", "Aliases", "Protection", "Value pattern", "Families"], rows) + [""]

    if sset.sources:
        out += ["## Sources", ""] + [f"- [{s.title}]({s.url})" for s in sset.sources] + [""]

    if sset.decisions:
        out += ["## Decision log (newest first)", ""]
        for d in sorted(sset.decisions, key=lambda x: x.date, reverse=True):
            who = f" ({d.by})" if d.by else ""
            out.append(f"- {d.date} **{d.status.upper()}**{who}: {d.text}")
        out.append("")

    return TaxonomyDoc(markdown="\n".join(out).rstrip() + "\n")
