"""Per-group field profile, as a basis for writing schemas. Counts only, no values."""
from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pykeepass import PyKeePass

from .models import FieldUsage, GroupProfile, InferReport
from .source import _gpath, _in_bin, _totp_style


def infer(kp: PyKeePass) -> InferReport:
    rb = kp.recyclebin_group
    bin_uuid = rb.uuid if rb is not None else None
    groups: dict[str, dict] = {}
    for e in kp.entries:
        if bin_uuid is not None and _in_bin(e.group, bin_uuid):
            continue
        g = groups.setdefault(
            e.group.name or "/",
            {"paths": set(), "n": 0, "user": 0, "url": 0, "notes": 0, "expiry": 0, "totp": 0, "https": 0,
             "fields": Counter(), "prot": Counter()},
        )
        props = e.custom_properties or {}
        g["paths"].add(_gpath(e.group))
        g["n"] += 1
        g["user"] += bool(e.username)
        g["url"] += bool(e.url)
        g["notes"] += bool(e.notes)
        g["expiry"] += bool(e.expires)
        g["totp"] += _totp_style(e, props) is not None
        g["https"] += (e.url or "").lower().startswith("https://")
        for key, val in props.items():
            if not val:
                continue
            g["fields"][key] += 1
            g["prot"][key] += bool(
                e._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key)
            )

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
