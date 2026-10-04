"""Reading a spreadsheet as a table of text: CSV and .xlsx. Data only; nothing is evaluated; hostile files are refused."""
import zipfile

import pytest
from pdh_testkit.xlsx import write_xlsx

from cprima_pdh import spreadsheet
from cprima_pdh.spreadsheet import SpreadsheetError, read_table

CELL_SECRET = "CELL-VALUE-THAT-MUST-NOT-BE-QUOTED"


# --- csv ---------------------------------------------------------------------------------------------------------------

def test_a_csv_is_a_header_and_rows_of_text(tmp_path):
    f = tmp_path / "t.csv"
    f.write_text("Title,UserName\nAcme,alex\nShop,\n", encoding="utf-8")
    t = read_table(f)
    assert t.kind == "csv" and t.header == ["Title", "UserName"]
    assert t.rows == [{"Title": "Acme", "UserName": "alex"}, {"Title": "Shop", "UserName": ""}]


def test_a_byte_order_mark_is_ignored(tmp_path):
    f = tmp_path / "t.csv"
    f.write_bytes(b"\xef\xbb\xbfTitle\nAcme\n")
    assert read_table(f).header == ["Title"]


def test_a_csv_that_is_not_utf8_says_so(tmp_path):
    f = tmp_path / "t.csv"
    f.write_bytes("Title\nCaf\xe9\n".encode("latin-1"))
    with pytest.raises(SpreadsheetError, match="not UTF-8"):
        read_table(f)


# --- xlsx --------------------------------------------------------------------------------------------------------------

ROWS = [["Group", "Title", "UserName", "account_no"], ["Shops", "Acme", "alex", 4711], ["Shops", "Beta", "sam", None]]


@pytest.mark.parametrize("shared", [True, False], ids=["shared strings", "inline strings"])
def test_an_xlsx_is_the_same_table(tmp_path, shared):
    t = read_table(write_xlsx(tmp_path / "t.xlsx", ROWS, shared=shared))
    assert t.kind == "xlsx" and t.header == ["Group", "Title", "UserName", "account_no"]
    assert t.rows == [{"Group": "Shops", "Title": "Acme", "UserName": "alex", "account_no": "4711"},
                      {"Group": "Shops", "Title": "Beta", "UserName": "sam", "account_no": ""}]


def test_numbers_are_the_digits_the_file_holds_and_booleans_are_words(tmp_path):
    t = read_table(write_xlsx(tmp_path / "t.xlsx", [["a", "b", "c"], [12, 1.5, True]]))
    assert t.rows == [{"a": "12", "b": "1.5", "c": "true"}]


def test_empty_rows_and_unused_columns_are_dropped_and_gaps_are_empty_cells(tmp_path):
    t = read_table(write_xlsx(tmp_path / "t.xlsx", [["Title", "", "Notes", ""], ["a", None, "n", None], [None, None, None, None], ["b"]]))
    assert t.header == ["Title", "", "Notes"]
    assert t.rows == [{"Title": "a", "": "", "Notes": "n"}, {"Title": "b", "": "", "Notes": ""}]


def test_the_first_visible_sheet_is_read(tmp_path):
    t = read_table(write_xlsx(tmp_path / "t.xlsx", sheets=[("Hidden", [["x"], ["no"]], "hidden"), ("Data", [["Title"], ["yes"]], "visible")]))
    assert t.rows == [{"Title": "yes"}]


def test_a_formula_is_never_evaluated_only_its_stored_value_is_read(tmp_path):
    body = ('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            '<row r="1"><c r="A1" t="inlineStr"><is><t>Title</t></is></c><c r="B1" t="inlineStr"><is><t>Note</t></is></c></row>'
            '<row r="2"><c r="A2" t="inlineStr"><is><t>a</t></is></c><c r="B2"><f>1+1</f><v>2</v></c></row>'
            '<row r="3"><c r="A3" t="inlineStr"><is><t>b</t></is></c><c r="B3"><f>HYPERLINK("http://x","y")</f></c></row>'
            "</sheetData></worksheet>")
    t = read_table(write_xlsx(tmp_path / "t.xlsx", [["x"]], sheet_xml_override={1: body}))
    assert t.rows == [{"Title": "a", "Note": "2"}, {"Title": "b", "Note": ""}]  # no stored value: empty, not evaluated


def test_rich_text_runs_are_joined_and_phonetic_hints_are_left_out(tmp_path):
    shared = ('<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              "<si><t>Title</t></si><si><r><t>Ac</t></r><r><t>me</t></r><rPh><t>PHONETIC</t></rPh></si></sst>")
    body = ('<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            '<row r="1"><c r="A1" t="s"><v>0</v></c></row><row r="2"><c r="A2" t="s"><v>1</v></c></row></sheetData></worksheet>')
    t = read_table(write_xlsx(tmp_path / "t.xlsx", [["x"]], sheet_xml_override={1: body}, shared_strings_xml=shared))
    assert t.rows == [{"Title": "Acme"}]


def test_a_workbook_with_nothing_in_it_is_an_empty_table(tmp_path):
    assert read_table(write_xlsx(tmp_path / "t.xlsx", [])).rows == []


# --- what is refused ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("suffix,kind", [(".xlsm", "macro-enabled"), (".xls", "binary"), (".xlsb", "binary"), (".ods", "OpenDocument")])
def test_formats_that_can_carry_more_than_data_are_refused_by_name(tmp_path, suffix, kind):
    f = tmp_path / f"t{suffix}"
    f.write_bytes(b"whatever")
    with pytest.raises(SpreadsheetError, match=f"{kind} spreadsheets are not read"):
        read_table(f)


def test_a_workbook_with_macros_is_refused(tmp_path):
    f = write_xlsx(tmp_path / "t.xlsx", ROWS, extra_parts={"xl/vbaProject.bin": b"\x00macro"})
    with pytest.raises(SpreadsheetError, match="contains macros"):
        read_table(f)


def test_a_workbook_that_links_to_other_workbooks_is_refused(tmp_path):
    f = write_xlsx(tmp_path / "t.xlsx", ROWS, extra_parts={"xl/externalLinks/externalLink1.xml": b"<externalLink/>"})
    with pytest.raises(SpreadsheetError, match="links to other workbooks"):
        read_table(f)


@pytest.mark.parametrize("declaration", ['<!DOCTYPE x [<!ENTITY a "aaaa">]>', '<!ENTITY a "aaaa">'], ids=["doctype", "entity"])
def test_a_workbook_that_declares_xml_entities_is_refused_without_quoting_a_cell(tmp_path, declaration):
    body = (f'<?xml version="1.0"?>{declaration}<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            f'<row r="1"><c r="A1" t="inlineStr"><is><t>{CELL_SECRET}</t></is></c></row></sheetData></worksheet>')
    f = write_xlsx(tmp_path / "t.xlsx", [["x"]], sheet_xml_override={1: body})
    with pytest.raises(SpreadsheetError, match="declares XML entities") as raised:
        read_table(f)
    assert CELL_SECRET not in str(raised.value)


def test_a_part_that_expands_unreasonably_is_refused(tmp_path):
    f = write_xlsx(tmp_path / "t.xlsx", ROWS, extra_parts={"xl/media/bomb.bin": b"\x00" * (8 * 1024 * 1024)})
    with pytest.raises(SpreadsheetError, match="zip bomb"):
        read_table(f)


def test_a_part_larger_than_the_limit_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(spreadsheet, "MAX_MEMBER_BYTES", 100)
    with pytest.raises(SpreadsheetError, match="larger than"):
        read_table(write_xlsx(tmp_path / "t.xlsx", ROWS))


def test_too_many_rows_are_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(spreadsheet, "MAX_ROWS", 2)
    with pytest.raises(SpreadsheetError, match="more than 2 rows"):
        read_table(write_xlsx(tmp_path / "t.xlsx", ROWS))


def test_a_file_that_is_not_a_workbook_is_refused(tmp_path):
    f = tmp_path / "t.xlsx"
    f.write_text("Title\nAcme\n", encoding="utf-8")
    with pytest.raises(SpreadsheetError, match="not an .xlsx workbook"):
        read_table(f)


def test_a_workbook_with_no_visible_sheet_is_refused(tmp_path):
    with pytest.raises(SpreadsheetError, match="no visible sheet"):
        read_table(write_xlsx(tmp_path / "t.xlsx", sheets=[("Hidden", [["x"]], "hidden")]))


def test_a_workbook_with_a_missing_part_or_broken_xml_is_refused(tmp_path):
    broken = write_xlsx(tmp_path / "b.xlsx", ROWS, sheet_xml_override={1: "<worksheet><oops>"})
    with pytest.raises(SpreadsheetError, match="not valid XML"):
        read_table(broken)
    plain = tmp_path / "p.xlsx"
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("hello.txt", "x")
    with pytest.raises(SpreadsheetError, match="not a valid workbook"):
        read_table(plain)
