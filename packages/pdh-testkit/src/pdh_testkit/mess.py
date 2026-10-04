"""A messy vault: every KDBX feature a real vault can have, with invented data only.

The owner's own vault is not a test source (its mess is one person's mess); this builds the variety instead: history,
attachments, tags, icons, colours, URL override, auto-type, expiry, `PreviousParentGroup`, a recycle bin (or none),
group notes and icons, duplicate titles, explicit `Protected="False"`, reference values and a deep tree.

Synthetic (pykeepass, key derivation lowered): for unit and integration tests, never end-to-end.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lxml import etree


from .vault import DEFAULT_PASSWORD, fresh_database

FEATURES = ("history", "attachments", "tags", "icons", "colours", "override-url", "autotype", "expiry",
            "previous-parent", "recycle-bin", "group-notes", "duplicate-titles", "protection-flags", "references",
            "deep-tree")


@dataclass(frozen=True)
class Messy:
    path: Path
    password: str = DEFAULT_PASSWORD
    features: tuple[str, ...] = field(default_factory=tuple)


def messy_vault(path: Path, recycle_bin: bool = True) -> Messy:
    """Write the messy vault to `path` (KDBX 4.0) and describe it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    kp = fresh_database(path, DEFAULT_PASSWORD)
    now = datetime.now(timezone.utc)
    root = kp.root_group
    money = kp.add_group(root, "Money")
    other = kp.add_group(root, "Other")
    kp.add_group(root, "Notes group", icon="5", notes="about this group")

    # history: the entry was changed three times, so it holds three earlier states
    h = kp.add_entry(money, "With history", "u", "pw-0", url="https://h.example.org")
    for n in (1, 2, 3):
        h.save_history()
        h.password = f"pw-{n}"

    # attachments
    a = kp.add_entry(money, "With attachments", "u", "pw")
    a.add_attachment(kp.add_binary(b"hello", compressed=False, protected=False), "note.txt")
    a.add_attachment(kp.add_binary(bytes(range(16)), compressed=False, protected=False), "data.bin")

    # tags, icon
    t = kp.add_entry(money, "Tagged", "u", "pw", tags=["one", "two", "three"], icon="12")

    # colours, override URL, auto-type
    c = kp.add_entry(money, "Coloured", "u", "pw")
    for tag, value in (("ForegroundColor", "#112233"), ("BackgroundColor", "#AABBCC"),
                       ("OverrideURL", "https://override.example.org")):
        el = c._element.find(tag)
        if el is None:
            el = etree.SubElement(c._element, tag)
        el.text = value
    c.autotype_enabled, c.autotype_sequence = False, "{PASSWORD}{ENTER}"

    # expiry: past, near, far
    for title, delta in (("Expired", -timedelta(days=30)), ("Soon", timedelta(days=10)), ("Far", timedelta(days=400))):
        e = kp.add_entry(other, title, "u", "pw")
        e.expiry_time, e.expires = now + delta, True

    # protection flags
    f = kp.add_entry(other, "Flags", "u", "pw")
    f.set_custom_property("secret_k", "s", protect=True)
    f.set_custom_property("plain_k", "p")
    f.set_custom_property("explicit_false", "x", protect=False)  # written as Protected="False"

    # reference value to another entry
    device = kp.add_entry(other, "Device", "u", "pw")
    link = kp.add_entry(other, "Linker", "u", "pw")
    link.set_custom_property("device", "{REF:T@I:" + device.uuid.hex.upper() + "}")

    # duplicate titles in two groups
    kp.add_entry(money, "Twin", "u1", "pw")
    kp.add_entry(other, "Twin", "u2", "pw")

    # a client-recorded origin (KeePassXC 2.7, KDBX 4.1)
    o = kp.add_entry(other, "Origin", "u", "pw")
    etree.SubElement(o._element, "PreviousParentGroup").text = base64.b64encode(money.uuid.bytes).decode()

    # a deep tree
    deep = root
    for name in ("Deep", "Deeper", "Deepest", "Bottom", "Floor"):
        deep = kp.add_group(deep, name)
    kp.add_entry(deep, "Deep entry", "u", "pw")

    features = [f for f in FEATURES if f != "recycle-bin"]
    if recycle_bin:
        kp.trash_entry(kp.add_entry(other, "In the bin", "u", "pw"))
        features.append("recycle-bin")
    kp.save()
    return Messy(path=path, features=tuple(features))
