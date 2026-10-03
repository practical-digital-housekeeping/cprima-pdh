"""`inspect find --in-fields` (custom field names and values) and `inspect entries --expired / --expiring DAYS`."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open

NOW = datetime.now(timezone.utc)


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("past", group="G", expires=NOW - timedelta(days=5)),
        Entry("soon", group="G", expires=NOW + timedelta(days=10)),
        Entry("later", group="G", expires=NOW + timedelta(days=200)),
        Entry("never", group="G", custom={"customer_no": "C-77", "other": "zzz"}, protected=frozenset({"other"})),
    ])


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


def titles(vault, *args):
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", *args, "-f", "json"])
    assert result.exit_code == 0, result.output
    return sorted(e["title"] for e in json.loads(result.stdout)["entries"])


def test_entries_without_a_filter_list_everything(vault):
    assert titles(vault, "entries") == ["later", "never", "past", "soon"]


def test_expired_lists_only_entries_past_their_expiry(vault):
    assert titles(vault, "entries", "--expired") == ["past"]


def test_expiring_lists_those_expiring_within_the_days_but_not_the_expired(vault):
    assert titles(vault, "entries", "--expiring", "30") == ["soon"]
    assert titles(vault, "entries", "--expiring", "365") == ["later", "soon"]


def test_the_two_filters_can_be_combined(vault):
    assert titles(vault, "entries", "--expired", "--expiring", "30") == ["past", "soon"]


def test_find_looks_at_standard_fields_only_by_default(vault):
    assert titles(vault, "find", "C-77") == []


def test_in_fields_searches_custom_field_names_and_values_including_protected_ones(vault):
    assert titles(vault, "find", "customer", "--in-fields") == ["never"]  # a field name
    assert titles(vault, "find", "c-77", "--in-fields") == ["never"]  # a value, case-insensitive
    assert titles(vault, "find", "zzz", "--in-fields") == ["never"]  # a protected value matches too


def test_in_fields_never_prints_a_value(vault):
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", "find", "zzz", "--in-fields", "-f", "json"])
    assert "zzz" not in result.stdout and "C-77" not in result.stdout
