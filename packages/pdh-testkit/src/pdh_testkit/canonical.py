"""The canonical vault: a copy of the genuine KDBX 4 template, filled from a taxonomy profile.

One owner group with every area of the profile below it, and one canonical entry per record type (plus one that
combines two): every required, recommended and optional field filled with an obviously fake value, protection as the
vocabulary demands, expiry dates where a record type wants one, links resolved. Every entry conforms to the profile.

Provenance: the file is *filled by this module with pykeepass* on top of a copy of a genuine KeePassXC template. That
is fine for unit and integration tests; it is not a genuine client-made vault, so it never serves end-to-end tests.
Regenerate it with `just canonical` (or `python -m pdh_testkit.canonical`) after changing a profile.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from pykeepass import PyKeePass

from .vaults import VAULT_DIR, load

OWNER = "Owner"  # the taxonomy's own axis name; one owner group is enough for a fixture
PASSWORD = "canonical-test"
NAME = "canonical-kdbx4"
TEMPLATE = "template-kdbx4"

# per profile: entries that combine record types (a fixture decision of the test kit, not part of a profile)
COMBINED = {"pdh-default": [["onlineshop", "website"]]}
EXPIRY = datetime(2030, 1, 1, tzinfo=timezone.utc)


def link_targets(sset) -> set[str]:
    """The record types some other record type links to: they are built first and are reached on a local address."""
    return {t for d in sset.schemas.values() for targets in d.links.values() for t in targets}


def entry_plan(names: list[str], sset) -> dict:
    """What one canonical entry holds: title, standard fields, custom fields with their protection, expiry."""
    from cprima_pdh.backends.kdbx_format import STANDARD_ATTR  # the standard fields are the profile's; the backend maps them
    from cprima_pdh.schema import _merge, resolve

    flat = None
    for n in names:
        d = resolve(sset.schemas[n], sset.facets)
        flat = d if flat is None else _merge(flat, d)
    named = [*flat.required, *flat.recommended, *flat.optional, *flat.links]
    plan = {"title": f"{' + '.join(names)} example", "standard": {}, "custom": {}, "protected": set(),
            "expires": flat.expires, "schema": ", ".join(names)}
    device = any(n in link_targets(sset) for n in names)
    for f in dict.fromkeys(named):
        if f == "Title":
            continue
        if f in STANDARD_ATTR:
            # a device is reached on a local address (a documentation address, RFC 5737); everything else is the profile's
            plan["standard"][f] = "http://192.0.2.1/" if f == "URL" and device else sset.example_of_standard(f)
        elif sset.is_link(f):
            plan["custom"][f] = None  # filled with a reference once the target exists
        else:
            plan["custom"][f] = sset.example_of(f) or "example"
            if f in sset.fields and sset.fields[f].protected is True:
                plan["protected"].add(f)
    return plan


def build(dest: Path, sset, template: Path | None = None) -> Path:
    """Write the canonical vault for `sset` to `dest` (a copy of the template, filled) and return `dest`."""
    from cprima_pdh.schema import make_ref

    src = load(TEMPLATE)
    shutil.copyfile(template or src.path, dest)
    kp = PyKeePass(str(dest), password=src.password)
    owner = kp.add_group(kp.root_group, OWNER)
    groups = {area: kp.add_group(owner, area) for area in sset.areas}

    targets = link_targets(sset)
    combos = [[n] for n in sorted(sset.schemas, key=lambda n: (n not in targets, n))]
    combos += COMBINED.get(sset.profile.full_name if sset.profile else "", [])  # entries that carry two record types
    made: dict[str, object] = {}
    for names in combos:
        p = entry_plan(names, sset)
        area = groups[sset.schemas[names[0]].area]  # the profile says where a record type belongs
        std = p["standard"]
        e = kp.add_entry(area, p["title"], std.get("UserName", ""), std.get("Password", ""),
                         url=std.get("URL"), notes=std.get("Notes"))
        e.set_custom_property(sset.binding.field, p["schema"])
        for field, value in p["custom"].items():
            if value is None:  # a link: the first device-like entry this record type may point at
                targets = next(iter(sset.schemas[names[0]].links.values()), [])
                value = make_ref(next(made[t].uuid for t in targets if t in made))
            e.set_custom_property(field, value, protect=field in p["protected"])
        if p["expires"]:
            e.expiry_time, e.expires = EXPIRY, True
        made.setdefault(names[0], e)
    kp.password = PASSWORD
    kp.save()
    return dest


def write_sidecar(dest: Path) -> Path:
    side = dest.with_suffix(".toml")
    side.write_text(
        f'# Sidecar of {dest.name}: the genuine template, filled by pdh-testkit. NOT a client-made vault.\n'
        f'# Throwaway test password; never use it for anything real.\n'
        f'password = "{PASSWORD}"\n'
        f'client = "KeePassXC"\n'
        f'format = "KDBX 4.0"\n'
        f'filled_by = "pdh-testkit canonical builder (pykeepass), on a copy of {TEMPLATE}.kdbx"\n'
        f'description = "One owner group, every area of the default profile, one canonical entry per record type. '
        f'Every entry conforms. Unit and integration tests only; regenerate with `just canonical`."\n',
        encoding="utf-8")
    return side


def main() -> None:
    from cprima_pdh import profiles

    dest = VAULT_DIR / f"{NAME}.kdbx"
    build(dest, profiles.load(profiles.DEFAULT))
    write_sidecar(dest)
    print(f"wrote {dest} and {dest.with_suffix('.toml').name}")


if __name__ == "__main__":
    main()
