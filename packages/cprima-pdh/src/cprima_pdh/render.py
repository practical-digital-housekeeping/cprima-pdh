"""Output adapters. Every renderer writes to a TextIO (stdout by default)."""
from __future__ import annotations

from enum import Enum
from typing import Iterator, Protocol, TextIO

from pydantic import BaseModel

from .models import EntryList, GroupNode, TaxonomyDoc


class Format(str, Enum):
    text = "text"
    json = "json"
    markdown = "markdown"


class Renderer(Protocol):
    def render(self, data: BaseModel, out: TextIO) -> None: ...


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


class JsonRenderer:
    def render(self, data: BaseModel, out: TextIO) -> None:
        out.write(data.model_dump_json(indent=2) + "\n")


class TextRenderer:
    def __init__(self, ascii_only: bool = False) -> None:
        self.mid, self.last, self.bar, self.gap = (
            ("|-- ", "`-- ", "|   ", "    ") if ascii_only else ("├── ", "└── ", "│   ", "    ")
        )

    def render(self, data: BaseModel, out: TextIO) -> None:
        if isinstance(data, TaxonomyDoc):  # already Markdown, readable as text too
            out.write(data.markdown)
        elif isinstance(data, GroupNode):
            out.write(f"{data.name}/  ({data.entry_count})\n")
            self._tree(data, "", out)
        elif isinstance(data, EntryList):
            for r in data.entries:
                extra = f"  #{','.join(r.tags)}" if r.tags else ""
                out.write(f"{r.group}/{r.title}  [{r.username}]  {r.url}{extra}\n")
        else:
            for line in _lines(data):
                out.write(line + "\n")

    def _tree(self, node: GroupNode, prefix: str, out: TextIO) -> None:
        kids = [("g", c) for c in node.children] + [("e", t) for t in node.entries]
        for i, (kind, item) in enumerate(kids):
            last = i == len(kids) - 1
            branch = self.last if last else self.mid
            if kind == "g":
                out.write(f"{prefix}{branch}{item.name}/  ({item.entry_count})\n")
                self._tree(item, prefix + (self.gap if last else self.bar), out)
            else:
                out.write(f"{prefix}{branch}{item}\n")


class MarkdownRenderer(TextRenderer):
    def render(self, data: BaseModel, out: TextIO) -> None:
        if isinstance(data, TaxonomyDoc):
            out.write(data.markdown)
            return
        if isinstance(data, (GroupNode, EntryList)):
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
