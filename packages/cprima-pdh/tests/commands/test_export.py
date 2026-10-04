"""`pdh io export-*`: the only commands that write outside the vault, and only to the file given with --out."""
import csv
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD
from pdh_testkit.mess import messy_vault
from pykeepass import PyKeePass

from cprima_pdh.source import pykeepass_open
from pdh_testkit.cli import invoke

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


def rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# --- export-attachment ---------------------------------------------------------------------------------------------

def test_an_attachment_is_written_byte_for_byte_to_the_given_file(vault, tmp_path):
    out = tmp_path / "out.bin"
    result = invoke(vault, "io", "export-attachment", "Money/With attachments", "data.bin", "--out", str(out), "-f", "json")
    assert result.exit_code == 0 and out.read_bytes() == bytes(range(16))
    assert json.loads(result.stdout)["bytes"] == 16


def test_export_attachment_refuses_an_existing_file_an_unknown_name_and_no_out_option(vault, tmp_path):
    out = tmp_path / "exists.bin"
    out.write_bytes(b"keep")
    assert invoke(vault, "io", "export-attachment", "Money/With attachments", "data.bin", "--out", str(out)).exit_code == 2
    assert out.read_bytes() == b"keep"
    assert invoke(vault, "io", "export-attachment", "Money/With attachments", "zzz", "--out", str(tmp_path / "n")).exit_code == 2
    assert invoke(vault, "io", "export-attachment", "Money/With attachments", "data.bin").exit_code == 2


# --- export-csv ----------------------------------------------------------------------------------------------------

def test_csv_has_no_secrets_by_default(vault, tmp_path):
    out = tmp_path / "e.csv"
    assert invoke(vault, "io", "export-csv", "--out", str(out)).exit_code == 0
    text = out.read_text(encoding="utf-8")
    assert "pw-" not in text and "Password" not in rows(out)[0]  # no password column, no password anywhere
    by = {r["Title"]: r for r in rows(out)}
    assert by["Tagged"]["Group"] == "Money" and by["Tagged"]["Tags"] == "one;two;three"
    assert "In the bin" not in by  # the recycle bin is not exported
    assert by["Flags"]["plain_k"] == "p"
    assert "secret_k" not in rows(out)[0]  # a protected field has no column at all: import-csv would refuse an empty one too


def test_there_is_no_way_to_export_secrets(vault, tmp_path):
    out = tmp_path / "e.csv"
    result = invoke(vault, "io", "export-csv", "--out", str(out), "--with-secrets")
    assert result.exit_code == 2 and "No such option" in (result.stderr or result.output) and not out.exists()


def test_a_cell_a_spreadsheet_would_run_as_a_formula_is_written_as_text(tmp_path):
    from pdh_testkit import Entry, synthetic_vault

    db = synthetic_vault(tmp_path / "f.kdbx", [Entry("=1+1", group="G", username="@cmd", notes="-2+3", url="https://ok.example.org")])
    out = tmp_path / "f.csv"
    assert invoke(db, "io", "export-csv", "--out", str(out)).exit_code == 0
    row = rows(out)[0]
    assert (row["Title"], row["UserName"], row["Notes"], row["URL"]) == ("'=1+1", "'@cmd", "'-2+3", "https://ok.example.org")


def test_csv_refuses_an_existing_file_and_writes_nothing_without_out(vault, tmp_path):
    out = tmp_path / "e.csv"
    out.write_text("keep")
    assert invoke(vault, "io", "export-csv", "--out", str(out)).exit_code == 2 and out.read_text() == "keep"
    assert invoke(vault, "io", "export-csv").exit_code == 2


def test_the_report_names_the_file_and_counts_never_a_value(vault, tmp_path):
    out = tmp_path / "e.csv"
    result = invoke(vault, "io", "export-csv", "--out", str(out), "-f", "json")
    report = json.loads(result.stdout)
    assert report["entries"] > 0 and "pw-" not in result.stdout


# --- export-kdbx ---------------------------------------------------------------------------------------------------

def test_a_copy_under_a_new_password_has_the_same_entries(vault, tmp_path):
    out = tmp_path / "copy.kdbx"
    before = vault.read_bytes()
    result = invoke(vault, "io", "export-kdbx", "--out", str(out), env={"PDH_NEW_PASSWORD": "copy-pw"})
    assert result.exit_code == 0 and vault.read_bytes() == before  # the original is untouched
    copy, original = PyKeePass(str(out), password="copy-pw"), pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert sorted(str(e.uuid) for e in copy.entries) == sorted(str(e.uuid) for e in original.entries)
    with pytest.raises(Exception):
        PyKeePass(str(out), password=DEFAULT_PASSWORD)  # the copy has its own password


def test_export_kdbx_refuses_an_existing_file_and_a_missing_password(vault, tmp_path):
    out = tmp_path / "copy.kdbx"
    out.write_bytes(b"keep")
    assert invoke(vault, "io", "export-kdbx", "--out", str(out), env={"PDH_NEW_PASSWORD": "x"}).exit_code == 2
    assert invoke(vault, "io", "export-kdbx", "--out", str(tmp_path / "n.kdbx"), env={}).exit_code == 2
