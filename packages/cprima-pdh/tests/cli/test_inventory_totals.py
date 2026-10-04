"""`inspect inventory`: history and attachment totals (counts and bytes only), the same numbers `doctor` shows."""
import json

import pytest
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh.cli import app

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


@pytest.fixture
def vault(tmp_path):
    return messy_vault(tmp_path / "m.kdbx").path


def test_the_inventory_counts_snapshots_and_attachment_bytes(vault):
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", "inventory", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0
    assert data["history"]["snapshots"] == 3 and data["history"]["entries_with_history"] == 1
    assert data["history"]["bytes"] > 0
    assert data["fields"]["attachment_count"] == 2 and data["fields"]["attachment_bytes"] == 21  # 5 + 16 bytes


def test_no_value_is_reported(vault):
    out = CliRunner().invoke(app, ["--db", str(vault), "inspect", "inventory", "-f", "json"]).stdout
    assert "pw-" not in out and "hello" not in out


def test_the_text_form_shows_the_totals(vault):
    out = CliRunner().invoke(app, ["--db", str(vault), "inspect", "inventory"]).stdout
    assert "snapshots" in out and "attachment_bytes" in out
