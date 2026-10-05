"""Per-group field profile, as a basis for writing schemas. Counts only, no values."""
from __future__ import annotations

from collections import Counter

from .models import FieldUsage, GroupProfile, InferReport
from .source import _totp_style_of
from cprima_pdh_vault.vault import as_vault


def infer(source) -> InferReport:
    groups: dict[str, dict] = {}
    for e in as_vault(source).entries():
        if e.in_bin:
            continue
        name = e.group_path.rsplit("/", 1)[-1] if e.group_path != "/" else "/"  # the leaf group name; repeated names merge
        g = groups.setdefault(
            name,
            {"paths": set(), "n": 0, "user": 0, "url": 0, "notes": 0, "expiry": 0, "totp": 0, "https": 0,
             "fields": Counter(), "prot": Counter()},
        )
        g["paths"].add(e.group_path)
        g["n"] += 1
        g["user"] += bool(e.username)
        g["url"] += bool(e.url)
        g["notes"] += bool(e.notes)
        g["expiry"] += bool(e.expires)
        g["totp"] += _totp_style_of(e) is not None
        g["https"] += e.url.lower().startswith("https://")
        for key, field in e.fields.items():
            if not field.value:
                continue
            g["fields"][key] += 1
            g["prot"][key] += field.protected

    profiles = [
        GroupProfile(
            name=name,
            paths=sorted(g["paths"]),
            entries=g["n"],
            with_username=g["user"],
            with_url=g["url"],
            with_notes=g["notes"],
            with_expiry=g["expiry"],
            with_totp=g["totp"],
            https_urls=g["https"],
            custom_fields=[
                FieldUsage(name=k, entries=n, protected=g["prot"][k]) for k, n in g["fields"].most_common()
            ],
        )
        for name, g in groups.items()
    ]
    profiles.sort(key=lambda p: (-p.entries, p.name))
    return InferReport(profiles=profiles)
