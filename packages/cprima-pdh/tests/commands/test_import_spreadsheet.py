"""`io import-csv` and `io import-xlsx`: structure only, each for its own format. Secrets are not in the file; the report says
how many are still to fill."""
import json
from datetime import date

import pytest
from pdh_testkit import DEFAULT_PASSWORD, synthetic_vault
from pdh_testkit.cli import invoke
from pdh_testkit.xlsx import write_xlsx

from cprima_pdh import profiles
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")

BINDING = profiles.load(profiles.DEFAULT).binding.field
HEADER = ["Group", "Title", "UserName", "URL", "Tags", "Expires", "account_no"]


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "target.kdbx")


def entries(db):
    return {e.title: e for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries}


def run(db, file, *extra):
    """Import with the command for the file's own format."""
    command = "import-xlsx" if str(file).lower().endswith((".xlsx", ".xlsm", ".xls", ".xlsb")) else "import-csv"
    return invoke(db, "io", command, str(file), "--group", "Imported", "-f", "json", *extra)


def test_a_workbook_is_imported_like_a_csv(vault, tmp_path):
    f = write_xlsx(tmp_path / "in.xlsx", [HEADER,
                                          ["Shops/Online", "Acme", "alex", "https://acme.example.org", "a;b", "2031-02-03", 4711],
                                          ["Shops", "Beta", "sam", None, None, None, None]])
    plan = json.loads(run(vault, f).stdout)
    assert plan["kind"] == "xlsx" and plan["entries"] == 2 and plan["columns"] == ["account_no"] and plan["applied"] is False
    assert json.loads(run(vault, f, "--apply").stdout)["applied"] is True
    acme = entries(vault)["Acme"]
    assert "/".join(acme.group.path) == "Imported/Shops/Online" and acme.username == "alex"
    assert acme.tags == ["a", "b"] and acme.expiry_time.date().isoformat() == "2031-02-03"
    assert acme.get_custom_property("account_no") == "4711" and not acme.password


def test_an_excel_date_number_in_expires_is_a_date(vault, tmp_path):
    assert date(1899, 12, 30).toordinal() + 45000 == date(2023, 3, 15).toordinal()  # the known pair: day 45000 is 15 March 2023
    f = write_xlsx(tmp_path / "in.xlsx", [["Title", "Expires"], ["Acme", 45000]])
    assert run(vault, f, "--apply").exit_code == 0
    assert entries(vault)["Acme"].expiry_time.date().isoformat() == "2023-03-15"


def test_a_number_in_expires_is_not_a_date_in_a_csv(vault, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text("Title,Expires\nAcme,45000\n", encoding="utf-8")
    result = run(vault, f, "--apply")
    assert result.exit_code == 2 and "not a date" in result.stderr


@pytest.mark.parametrize("column", ["Password", "OTP", "api_token", "TimeOtp-Secret-Base32"])
def test_a_secret_column_in_a_workbook_is_refused_like_in_a_csv(vault, tmp_path, column):
    f = write_xlsx(tmp_path / "in.xlsx", [["Title", column], ["Acme", "hunter2-must-not-be-echoed"]])
    result = run(vault, f, "--apply")
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2 and f"column {column!r} is for a secret" in shown
    assert "hunter2-must-not-be-echoed" not in shown and entries(vault) == {}


@pytest.mark.parametrize("name,extra", [("macros.xlsx", {"xl/vbaProject.bin": b"x"}),
                                        ("links.xlsx", {"xl/externalLinks/e.xml": b"<x/>"})])
def test_a_workbook_that_can_do_more_than_hold_data_is_refused_and_changes_nothing(vault, tmp_path, name, extra):
    f = write_xlsx(tmp_path / name, [["Title"], ["Acme"]], extra_parts=extra)
    before = vault.read_bytes()
    result = run(vault, f, "--apply")
    assert result.exit_code == 2 and vault.read_bytes() == before


def test_a_macro_enabled_file_is_refused_by_its_name(vault, tmp_path):
    f = tmp_path / "in.xlsm"
    f.write_bytes(b"x")
    result = run(vault, f)
    assert result.exit_code == 2 and "macro-enabled spreadsheets are not read" in result.stderr


def test_a_workbook_without_a_title_column_is_refused(vault, tmp_path):
    result = run(vault, write_xlsx(tmp_path / "in.xlsx", [["UserName"], ["alex"]]))
    assert result.exit_code == 2 and "needs a Title column" in result.stderr


# --- the secret fields still to fill ----------------------------------------------------------------------------------

def test_every_imported_login_still_lacks_its_password(vault, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text("Title,UserName\nA,x\nB,y\nC,z\n", encoding="utf-8")
    assert json.loads(run(vault, f).stdout)["secrets_to_fill"] == 3


def test_a_typed_entry_counts_all_the_secret_fields_its_record_type_has(vault, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text(f"Title,{BINDING}\nHome wifi,wifi-access-point\nShop,website\n", encoding="utf-8")
    assert json.loads(run(vault, f).stdout)["secrets_to_fill"] == 2 + 1  # wifi_key and Password, then Password


def test_the_report_never_carries_a_value(vault, tmp_path):
    f = write_xlsx(tmp_path / "in.xlsx", [["Title", "UserName", "account_no"], ["Acme", "alex-unique-name", "4711-unique"]])
    plan = run(vault, f)
    assert "alex-unique-name" not in plan.stdout and "4711-unique" not in plan.stdout


# --- each command takes its own format ---------------------------------------------------------------------------------

def test_import_csv_refuses_a_workbook_and_says_which_command_to_use(vault, tmp_path):
    f = write_xlsx(tmp_path / "in.xlsx", [["Title"], ["Acme"]])
    before = vault.read_bytes()
    result = invoke(vault, "io", "import-csv", str(f), "--apply")
    assert result.exit_code == 2 and "is a workbook: use `pdh io import-xlsx`" in result.stderr and vault.read_bytes() == before


def test_import_xlsx_refuses_a_csv_file_and_says_which_command_to_use(vault, tmp_path):
    f = tmp_path / "in.csv"
    f.write_text("Title\nAcme\n", encoding="utf-8")
    before = vault.read_bytes()
    result = invoke(vault, "io", "import-xlsx", str(f), "--apply")
    assert result.exit_code == 2 and "is a CSV file: use `pdh io import-csv`" in result.stderr and vault.read_bytes() == before


@pytest.mark.parametrize("command", ["import-csv", "import-xlsx"])
def test_a_file_that_is_neither_is_refused_by_both(vault, tmp_path, command):
    f = tmp_path / "in.xlsm"
    f.write_bytes(b"x")
    result = invoke(vault, "io", command, str(f))
    assert result.exit_code == 2 and "macro-enabled spreadsheets are not read" in result.stderr


def test_import_xlsx_does_not_guess_that_a_text_file_is_a_workbook(vault, tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("Title\nAcme\n", encoding="utf-8")
    result = invoke(vault, "io", "import-xlsx", str(f))
    assert result.exit_code == 2 and "is not an .xlsx workbook" in result.stderr
