"""In-memory stand-ins for pykeepass objects: no file, no key derivation, no passwords.

An entry is described by plain properties (`E(...)`) or by a KDBX-shaped XML snippet
(`entries_from_xml`). Either way it becomes a lightweight `StubEntry` over a real lxml
`<Entry>` element, so the XPath rules run on exactly the structure KeePass uses.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from lxml import etree

RESERVED = {"Title", "UserName", "Password", "URL", "Notes", "otp"}


@dataclass
class StubGroup:
    path: list[str]  # names below the root, like pykeepass Group.path
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    parentgroup: object = None

    @property
    def name(self) -> str:
        return self.path[-1] if self.path else ""


class StubEntry:
    """The subset of pykeepass.Entry that kpcli uses, driven by an lxml <Entry> element."""

    def __init__(self, element: etree._Element, group: StubGroup):
        self._element = element
        self.group = group

    def _field(self, key: str) -> str | None:
        v = self._element.xpath("String[Key=$k]/Value", k=key)
        return None if not v else (v[0].text or "")

    title = property(lambda s: s._field("Title"))
    username = property(lambda s: s._field("UserName"))
    password = property(lambda s: s._field("Password"))
    url = property(lambda s: s._field("URL"))
    notes = property(lambda s: s._field("Notes"))
    otp = property(lambda s: s._field("otp"))

    @property
    def uuid(self) -> str:
        return self._element.findtext("UUID")

    @property
    def tags(self) -> list[str]:
        return [t for t in (self._element.findtext("Tags") or "").replace(",", ";").split(";") if t]

    @property
    def expires(self) -> bool:
        return self._element.findtext("Times/Expires") == "True"

    @property
    def custom_properties(self) -> dict[str, str]:
        out = {}
        for s in self._element.findall("String"):
            k = s.findtext("Key")
            if k not in RESERVED:
                out[k] = s.findtext("Value") or ""
        return out

    def get_custom_property(self, key: str) -> str | None:
        return self.custom_properties.get(key)

    def protected(self, key: str) -> bool:
        return bool(self._element.xpath("boolean(String[Key=$k]/Value[@Protected='True'])", k=key))


class StubKP:
    """A database with only what kpcli reads: entries, and optionally a recycle bin group."""

    def __init__(self, entries: list[StubEntry], recyclebin_group: StubGroup | None = None):
        self.entries = entries
        self.recyclebin_group = recyclebin_group
        self.groups = list({id(e.group): e.group for e in entries}.values())

    def find_entries(self, uuid=None, first=False, **_kw):  # the one lookup the write code uses
        hits = [e for e in self.entries if uuid is not None and str(e.uuid) == str(uuid)]
        return (hits[0] if hits else None) if first else hits


def _string(parent: etree._Element, key: str, value: str | None, protected: bool = False) -> None:
    s = etree.SubElement(parent, "String")
    etree.SubElement(s, "Key").text = key
    v = etree.SubElement(s, "Value")
    if value:  # KeePass writes empty values as <Value/>
        v.text = value
    if protected:
        v.set("Protected", "True")


def E(
    title: str = "Entry",
    username: str = "user",
    password: str = "secret-pw",
    url: str = "https://example.org",
    notes: str = "",
    schema: str | None = None,
    custom: dict[str, str] | None = None,
    protected: tuple[str, ...] = (),
    expires: bool = False,
    tags: tuple[str, ...] = (),
    group: str | StubGroup = "Area",
    totp: str | None = None,
) -> StubEntry:
    """Build an entry from properties. `protected` lists the custom fields that carry Protected="True"."""
    el = etree.Element("Entry")
    etree.SubElement(el, "UUID").text = str(uuid.uuid4())
    times = etree.SubElement(el, "Times")
    etree.SubElement(times, "Expires").text = "True" if expires else "False"
    if tags:
        etree.SubElement(el, "Tags").text = ";".join(tags)
    _string(el, "Title", title)
    _string(el, "UserName", username)
    _string(el, "Password", password, protected=True)
    _string(el, "URL", url)
    _string(el, "Notes", notes)
    if totp:
        _string(el, "otp", totp, protected=True)
    fields = dict(custom or {})
    if schema is not None:
        fields["_schema"] = schema
    for k, v in fields.items():
        _string(el, k, v, protected=k in protected)
    return StubEntry(el, group if isinstance(group, StubGroup) else StubGroup(group.split("/")))


def entries_from_xml(xml: str, default_group: str = "Area") -> list[StubEntry]:
    """Entries from a KDBX-shaped snippet: one <Entry>, several, or a whole <KeePassFile>."""
    root = etree.fromstring(xml)
    elements = [root] if root.tag == "Entry" else root.xpath("//Entry")
    out = []
    for el in elements:
        names = [g.findtext("Name") for g in el.xpath("ancestor::Group")]  # outermost first
        names = names[1:] if root.tag != "Entry" and names else names  # the outermost Group is the root group
        out.append(StubEntry(el, StubGroup(names or default_group.split("/"))))
    return out
