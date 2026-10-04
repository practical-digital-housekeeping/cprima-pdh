"""Reading a spreadsheet as a table of text: CSV, and .xlsx with the standard library only.

What a spreadsheet can carry is structure (see the README, "Data boundary"), so all this module does is turn a file into a
header and rows of text. It never evaluates anything: a formula cell is read as the value stored with it, a number as the digits
the file holds (format a column as text in the spreadsheet to keep leading zeros or long numbers). It refuses what could do
more than hold data: macro-enabled workbooks, binary and OpenDocument formats, links to other workbooks, a file that declares
XML entities (a decompression-by-entity attack), and a zip that expands unreasonably.
"""
from __future__ import annotations

import csv
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

MAX_ROWS = 100_000
MAX_COLUMNS = 256
MAX_MEMBER_BYTES = 100 * 1024 * 1024  # one part of the workbook, uncompressed
MAX_TOTAL_BYTES = 250 * 1024 * 1024
MAX_RATIO = 200  # uncompressed to compressed, for a part over a megabyte

_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_REFUSED_SUFFIXES = {".xlsm": "macro-enabled", ".xlsb": "binary", ".xls": "binary", ".ods": "OpenDocument", ".xltm": "macro-enabled"}


class SpreadsheetError(ValueError):
    """The file cannot be read as a table of data; the message says why and never quotes a cell."""


@dataclass(frozen=True)
class Table:
    header: list[str]
    rows: list[dict[str, str]]  # header -> text, every row has every header
    kind: str  # "csv" or "xlsx"


def _refuse_other_formats(path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix in _REFUSED_SUFFIXES:
        raise SpreadsheetError(f"{path.name}: {_REFUSED_SUFFIXES[suffix]} spreadsheets are not read; save it as .xlsx or .csv "
                               f"(a macro-free workbook, as data only)")


def read_csv(path: Path) -> Table:
    """A UTF-8 CSV file as a header and rows of text. A workbook is not a CSV file and is not guessed at."""
    path = Path(path)
    _refuse_other_formats(path)
    if path.suffix.lower() == ".xlsx":
        raise SpreadsheetError(f"{path.name} is a workbook, not a CSV file")
    return _read_csv(path)


def read_xlsx(path: Path) -> Table:
    """The first visible sheet of an .xlsx workbook as a header and rows of text. Anything else is refused."""
    path = Path(path)
    _refuse_other_formats(path)
    if path.suffix.lower() != ".xlsx":
        raise SpreadsheetError(f"{path.name} is not an .xlsx workbook")
    return _read_xlsx(path)


def read_table(path: Path) -> Table:
    """A table from a file by its kind: an .xlsx workbook through `read_xlsx`, anything else as CSV through `read_csv`."""
    return read_xlsx(path) if Path(path).suffix.lower() == ".xlsx" else read_csv(path)


# --- CSV ----------------------------------------------------------------------------------------------------------------

def _read_csv(path: Path) -> Table:
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            header = list(reader.fieldnames or [])
            rows = [{h: (raw.get(h) or "") for h in header} for raw in reader]
    except OSError as exc:
        raise SpreadsheetError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except UnicodeDecodeError:
        raise SpreadsheetError(f"{path.name} is not UTF-8 text; save it as CSV UTF-8") from None
    return Table(header, rows, "csv")


# --- XLSX ---------------------------------------------------------------------------------------------------------------

def _read_xlsx(path: Path) -> Table:
    try:
        if not zipfile.is_zipfile(path):
            raise SpreadsheetError(f"{path.name} is not an .xlsx workbook (a password-protected or damaged file is not read)")
        with zipfile.ZipFile(path) as z:
            _check_package(z, path.name)
            sheet = _first_sheet_member(z, path.name)
            shared = _shared_strings(z)
            grid = _cells(_xml(z, sheet, path.name), shared)
    except OSError as exc:
        raise SpreadsheetError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except zipfile.BadZipFile:
        raise SpreadsheetError(f"{path.name} is damaged") from None
    if not grid:
        return Table([], [], "xlsx")
    width = min(max(len(r) for r in grid), MAX_COLUMNS)
    header = [(c or "").strip() for c in (grid[0] + [""] * width)[:width]]
    while header and not header[-1]:
        header.pop()  # unused columns at the right
    rows = []
    for raw in grid[1:]:
        cells = (raw + [""] * len(header))[:len(header)]
        if any(c.strip() for c in cells):
            rows.append(dict(zip(header, cells)))
    return Table(header, rows, "xlsx")


def _check_package(z: zipfile.ZipFile, name: str) -> None:
    total = 0
    for info in z.infolist():
        lowered = info.filename.lower()
        if lowered == "xl/vbaproject.bin" or lowered.startswith("xl/vbaproject"):
            raise SpreadsheetError(f"{name} contains macros; pdh does not read macro-enabled workbooks")
        if lowered.startswith("xl/externallinks/"):
            raise SpreadsheetError(f"{name} links to other workbooks; pdh reads self-contained data only")
        if info.file_size > MAX_MEMBER_BYTES:
            raise SpreadsheetError(f"{name}: a part of the workbook is larger than {MAX_MEMBER_BYTES // (1024 * 1024)} MB uncompressed")
        if info.file_size > 1024 * 1024 and info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
            raise SpreadsheetError(f"{name}: a part of the workbook expands unreasonably (a zip bomb)")
        total += info.file_size
    if total > MAX_TOTAL_BYTES:
        raise SpreadsheetError(f"{name} is larger than {MAX_TOTAL_BYTES // (1024 * 1024)} MB uncompressed")


def _xml(z: zipfile.ZipFile, member: str, name: str) -> ET.Element:
    try:
        data = z.read(member)
    except KeyError:
        raise SpreadsheetError(f"{name} is not a valid workbook (no {member})") from None
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise SpreadsheetError(f"{name} declares XML entities; pdh does not read it")
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        raise SpreadsheetError(f"{name} is damaged ({member} is not valid XML)") from None


def _first_sheet_member(z: zipfile.ZipFile, name: str) -> str:
    workbook = _xml(z, "xl/workbook.xml", name)
    rels = {r.get("Id"): r.get("Target", "") for r in _xml(z, "xl/_rels/workbook.xml.rels", name).iter(f"{_PKG_REL}Relationship")}
    for sheet in workbook.iter(f"{_MAIN}sheet"):
        if sheet.get("state") in ("hidden", "veryHidden"):
            continue
        target = rels.get(sheet.get(f"{_REL}id"), "")
        if target:
            return target.lstrip("/") if target.startswith("/") else "xl/" + target
    raise SpreadsheetError(f"{name} has no visible sheet")


def _text(element: ET.Element) -> str:
    """The text of a string item: its plain text and its runs, without phonetic hints (`rPh`)."""
    parts: list[str] = []
    for child in element:
        if child.tag == f"{_MAIN}t":
            parts.append(child.text or "")
        elif child.tag == f"{_MAIN}r":
            parts.extend(t.text or "" for t in child.iter(f"{_MAIN}t"))
    return "".join(parts)


def _shared_strings(z: zipfile.ZipFile) -> list[str]:
    try:
        z.getinfo("xl/sharedStrings.xml")
    except KeyError:
        return []
    return [_text(si) for si in _xml(z, "xl/sharedStrings.xml", "the workbook").iter(f"{_MAIN}si")]


_REF = re.compile(r"^([A-Z]+)([0-9]+)$")


def _column(ref: str) -> int:
    letters = _REF.match(ref).group(1) if _REF.match(ref) else ""
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _cells(sheet: ET.Element, shared: list[str]) -> list[list[str]]:
    grid: list[list[str]] = []
    for row in sheet.iter(f"{_MAIN}row"):
        if len(grid) >= MAX_ROWS:
            raise SpreadsheetError(f"more than {MAX_ROWS} rows; split the file")
        try:
            number = int(row.get("r", len(grid) + 1))
        except ValueError:
            number = len(grid) + 1
        if number > MAX_ROWS:
            raise SpreadsheetError(f"more than {MAX_ROWS} rows; split the file")
        while len(grid) < number - 1:
            grid.append([])
        values: list[str] = []
        for cell in row.iter(f"{_MAIN}c"):
            index = _column(cell.get("r", "")) if cell.get("r") else len(values)
            if index >= MAX_COLUMNS:
                continue
            while len(values) < index:
                values.append("")
            values.append(_cell_text(cell, shared))
        grid.append(values)
    return grid


def _cell_text(cell: ET.Element, shared: list[str]) -> str:
    kind = cell.get("t", "n")
    v = cell.find(f"{_MAIN}v")
    if kind == "inlineStr":
        inline = cell.find(f"{_MAIN}is")
        return _text(inline) if inline is not None else ""
    if v is None or v.text is None:
        return ""  # an empty cell, or a formula with no stored value: nothing is evaluated
    if kind == "s":
        try:
            return shared[int(v.text)]
        except (ValueError, IndexError):
            return ""
    if kind == "b":
        return "true" if v.text.strip() == "1" else "false"
    if kind == "e":
        return ""  # an error value (#N/A ...) is not data
    return v.text  # n, str: as the file holds it
