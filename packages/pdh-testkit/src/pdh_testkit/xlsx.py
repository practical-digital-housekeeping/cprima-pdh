"""Write small .xlsx workbooks for tests, with the standard library only (no spreadsheet package, no client).

A workbook is a zip of XML parts. `write_xlsx` writes the minimal valid one, and lets a test add parts or replace the sheet's
XML, which is how the hostile files are made (macros, links to other workbooks, entity declarations, a zip bomb).
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

Cell = str | int | float | bool | None

_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
_ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="xl/workbook.xml"/></Relationships>')
_NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
_R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'


def _ref(column: int, row: int) -> str:
    letters = ""
    n = column + 1
    while n:
        n, rest = divmod(n - 1, 26)
        letters = chr(65 + rest) + letters
    return f"{letters}{row}"


def sheet_xml(rows: list[list[Cell]], strings: list[str] | None) -> str:
    """The XML of one sheet. With `strings` given, text cells refer to it (shared strings); else they are inline strings."""
    out = []
    for r, cells in enumerate(rows, start=1):
        parts = []
        for c, value in enumerate(cells):
            ref = _ref(c, r)
            if value is None:
                continue
            if isinstance(value, bool):
                parts.append(f'<c r="{ref}" t="b"><v>{int(value)}</v></c>')
            elif isinstance(value, (int, float)):
                parts.append(f'<c r="{ref}"><v>{value}</v></c>')
            elif strings is not None:
                strings.append(value)
                parts.append(f'<c r="{ref}" t="s"><v>{len(strings) - 1}</v></c>')
            else:
                parts.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>')
        out.append(f'<row r="{r}">{"".join(parts)}</row>')
    return f'<?xml version="1.0" encoding="UTF-8"?><worksheet {_NS}><sheetData>{"".join(out)}</sheetData></worksheet>'


def write_xlsx(path: Path, rows: list[list[Cell]] | None = None, *, shared: bool = True, sheets: list[tuple[str, list[list[Cell]], str]] | None = None,
               sheet_xml_override: dict[int, str] | None = None, extra_parts: dict[str, bytes] | None = None,
               shared_strings_xml: str | None = None) -> Path:
    """Write a workbook. `rows` is the one sheet; `sheets` is [(name, rows, state)] for several (state "visible" or "hidden").
    `sheet_xml_override` replaces the XML of a sheet (by its number, from 1); `extra_parts` adds raw parts; `shared_strings_xml`
    replaces the shared strings part."""
    sheets = sheets or [("Sheet1", rows or [], "visible")]
    strings: list[str] | None = [] if shared else None
    bodies = [sheet_xml(r, strings) for _, r, _ in sheets]
    for number, text in (sheet_xml_override or {}).items():
        bodies[number - 1] = text
    workbook = (f'<?xml version="1.0" encoding="UTF-8"?><workbook {_NS} {_R}><sheets>' +
                "".join(f'<sheet name="{escape(name)}" sheetId="{i}" state="{state}" r:id="rId{i}"/>'
                        for i, (name, _, state) in enumerate(sheets, start=1)) + "</sheets></workbook>")
    rels = ('<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
                    f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1)) + "</Relationships>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CONTENT_TYPES)
        z.writestr("_rels/.rels", _ROOT_RELS)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        for i, body in enumerate(bodies, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", body)
        if shared_strings_xml is not None:
            z.writestr("xl/sharedStrings.xml", shared_strings_xml)
        elif strings:
            items = "".join(f"<si><t>{escape(s)}</t></si>" for s in strings)
            z.writestr("xl/sharedStrings.xml", f'<?xml version="1.0" encoding="UTF-8"?><sst {_NS}>{items}</sst>')
        for name, data in (extra_parts or {}).items():
            z.writestr(name, data)
    return path
