"""Output adapters: the only place that turns a result model into text, JSON or Markdown.

Every command returns a model and hands it to `get_renderer(...).render(model, stdout)`; no command prints results
itself. JSON is the model as it is; text and Markdown come from `to_text`, a registry keyed on the model type: a model
without an entry gets the generic key/value layout, so a new command works at once and can be given a nicer layout later.
"""
from __future__ import annotations

from enum import Enum
from functools import singledispatch
from typing import Iterator, Protocol, TextIO

from pydantic import BaseModel

from .models import (
    BackendList,
    DoctorReport,
    EntryList,
    FillReport,
    GroupNode,
    ProfileList,
    SessionState,
    TaxonomyDoc,
)


class Format(str, Enum):
    text = "text"
    json = "json"
    markdown = "markdown"


class Renderer(Protocol):
    def render(self, data: BaseModel, out: TextIO) -> None: ...


# --- the generic layout ----------------------------------------------------------------------------

def _items(obj) -> list[tuple[str, object]]:
    if isinstance(obj, BaseModel):
        return [(k, getattr(obj, k)) for k in type(obj).model_fields]
    return sorted(obj.items(), key=lambda kv: (-kv[1] if isinstance(kv[1], int) else 0, str(kv[0])))


def _lines(obj, depth: int = 0, bullet: str = "") -> Iterator[str]:
    pad = "  " * depth
    for key, val in _items(obj):
        if isinstance(val, (BaseModel, dict)):
            yield f"{pad}{bullet}{key}:"
            yield from _lines(val, depth + 1, bullet)
        elif isinstance(val, list) and val and isinstance(val[0], BaseModel):
            yield f"{pad}{bullet}{key}:"
            for item in val:
                yield f"{pad}  {bullet}{item}"
        elif isinstance(val, list):
            yield f"{pad}{bullet}{key}: " + (", ".join(map(str, val)) if val else "-")
        else:
            yield f"{pad}{bullet}{key}: {val}"


# --- text layouts, one per model that wants its own ----------------------------------------------------

@singledispatch
def to_text(data: BaseModel, ascii_only: bool = False) -> str | None:
    """The text layout of a model, or None for the generic key/value layout."""
    return None


@to_text.register
def _(data: TaxonomyDoc, ascii_only: bool = False) -> str:  # already Markdown, readable as text too
    return data.markdown


@to_text.register
def _(data: EntryList, ascii_only: bool = False) -> str:
    return "".join(
        f"{r.group}/{r.title}  [{r.username}]  {r.url}{'  #' + ','.join(r.tags) if r.tags else ''}\n" for r in data.entries)


@to_text.register
def _(data: FillReport, ascii_only: bool = False) -> str:
    lines = [f"{i.entry}: {i.field} ({i.how})\n" for i in data.items]
    lines.append(f"{data.fields} secret field(s) in {data.entries} entr{'y' if data.entries == 1 else 'ies'} under {data.target}: "
                 f"{data.generated} generated, {data.typed} typed, {data.skipped} skipped"
                 f"{'' if data.applied or not data.items else ' (a dry run: nothing was asked or written; add --apply)'}\n")
    return "".join(lines)


@to_text.register
def _(data: DoctorReport, ascii_only: bool = False) -> str:
    out, section = [], None
    for c in data.checks:
        if c.section != section:
            section = c.section
            out.append(f"{section}\n")
        out.append(f"  {str(c).replace(chr(10), chr(10) + '  ')}\n")
    return "".join(out)


@to_text.register
def _(data: BackendList, ascii_only: bool = False) -> str:
    out = []
    for b in data.backends:
        out.append(f"{b.name:10} {b.detail}\n")
        if b.detection:
            out.append(f"{'':10} recognised by: {b.detection}\n")
        if b.capabilities:
            out.append(f"{'':10} can: {', '.join(b.capabilities)}\n")
    return "".join(out)


@to_text.register
def _(data: ProfileList, ascii_only: bool = False) -> str:
    return "".join(f"{p.name:16} {p.version:8} {p.description}\n" for p in data.profiles)


@to_text.register
def _(data: SessionState, ascii_only: bool = False) -> str:
    if data.action == "unlocked":
        return f"unlocked for {data.minutes} min\n"
    if data.action == "locked":
        return "locked\n"
    if data.action == "no-session":
        return "no session\n"
    if not data.unlocked:
        return "locked\n"
    return f"unlocked, {data.seconds_left // 60}m{data.seconds_left % 60:02d}s left\n"


def _group_line(node: GroupNode) -> str:
    if node.kind == "recycle-bin":
        return f"{node.name}/  ({node.total}, not counted)"
    counts = f"{node.total}, {node.typed} typed" if node.typed else f"{node.total}"
    return f"{node.name}/  ({counts})" + (f"  <- {node.note}" if node.note else "") + (" ..." if node.collapsed else "")


@to_text.register
def _(data: GroupNode, ascii_only: bool = False) -> str:
    mid, last, bar, gap = ("|-- ", "`-- ", "|   ", "    ") if ascii_only else ("├── ", "└── ", "│   ", "    ")
    lines = [_group_line(data)]

    def walk(node: GroupNode, prefix: str) -> None:
        kids: list[tuple[str, object]] = [("g", c) for c in node.children] + [("e", t) for t in node.entries]
        for i, (kind, item) in enumerate(kids):
            is_last = i == len(kids) - 1
            branch = last if is_last else mid
            if kind == "g":
                lines.append(f"{prefix}{branch}{_group_line(item)}")
                walk(item, prefix + (gap if is_last else bar))
            else:
                written = ", ".join(item.schemas)
                derived = f"by fields: {', '.join(item.by_fields)}" if item.by_fields else ""
                tag = f"  [{'; '.join(p for p in (written, derived) if p) or '?'}]"
                lines.append(f"{prefix}{branch}{item.title}{tag}")

    walk(data, "")
    return "\n".join(lines) + "\n"


# --- the renderers ---------------------------------------------------------------------------------------

class JsonRenderer:
    def render(self, data: BaseModel, out: TextIO) -> None:
        out.write(data.model_dump_json(indent=2) + "\n")


class TextRenderer:
    def __init__(self, ascii_only: bool = False) -> None:
        self.ascii_only = ascii_only

    def render(self, data: BaseModel, out: TextIO) -> None:
        text = to_text(data, self.ascii_only)
        if text is not None:
            out.write(text)
            return
        for line in _lines(data):
            out.write(line + "\n")


class MarkdownRenderer(TextRenderer):
    FENCED = (GroupNode, EntryList)  # layouts that need a monospace block to survive Markdown

    def render(self, data: BaseModel, out: TextIO) -> None:
        if isinstance(data, TaxonomyDoc):
            out.write(data.markdown)
            return
        if isinstance(data, self.FENCED):
            out.write("```\n")
            super().render(data, out)
            out.write("```\n")
            return
        items = _items(data)
        nested = (BaseModel, dict)
        for key, val in items:  # scalars first, so they don't read as part of a section
            if not isinstance(val, nested):
                out.write(f"- {key}: {val}\n")
        for key, val in items:
            if isinstance(val, nested):
                out.write(f"\n## {key}\n\n")
                for line in _lines(val, 0, "- "):
                    out.write(line + "\n")


def get_renderer(fmt: Format, ascii_only: bool = False) -> Renderer:
    if fmt is Format.json:
        return JsonRenderer()
    if fmt is Format.markdown:
        return MarkdownRenderer(ascii_only)
    return TextRenderer(ascii_only)
