"""The session cache against the data boundary: encrypted at rest, deleted when it expires, and Windows-only said plainly."""
import os

import pytest
from pdh_testkit import Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh import session
from cprima_pdh.cli import app

windows_only = pytest.mark.skipif(os.name != "nt", reason="the session cache is encrypted with Windows DPAPI")
PASSPHRASE = "plain-secret-passphrase-xyz"


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])


def any_pdh_call():
    return CliRunner().invoke(app, ["method", "schemas"])


def test_the_suite_never_reaches_the_real_session_file():
    assert session.SESSION_FILE.name == "session-for-tests.bin"


@windows_only
def test_the_passphrase_is_not_in_the_file_as_plain_text(vault):
    session.save_session(vault, PASSPHRASE, None, 5)
    blob = session.SESSION_FILE.read_bytes()
    assert PASSPHRASE.encode() not in blob and PASSPHRASE.encode("utf-16-le") not in blob
    assert session.load_session(vault) == (PASSPHRASE, None)  # and the same user gets it back


@windows_only
def test_an_expired_session_is_deleted_by_the_next_pdh_call_of_any_kind(vault):
    session.save_session(vault, PASSPHRASE, None, -1)
    assert session.SESSION_FILE.exists()
    assert any_pdh_call().exit_code == 0
    assert not session.SESSION_FILE.exists()


@windows_only
def test_a_valid_session_stays_after_a_pdh_call(vault):
    session.save_session(vault, PASSPHRASE, None, 5)
    assert any_pdh_call().exit_code == 0
    assert session.SESSION_FILE.exists()


@windows_only
def test_lock_deletes_it_at_once(vault):
    session.save_session(vault, PASSPHRASE, None, 5)
    assert CliRunner().invoke(app, ["session", "lock"]).exit_code == 0
    assert not session.SESSION_FILE.exists()


def test_unlock_off_windows_says_what_to_use_instead(vault, monkeypatch):
    monkeypatch.setattr(session, "supported", lambda: False)
    result = CliRunner().invoke(app, ["--db", str(vault), "session", "unlock"])
    assert result.exit_code == 2 and "KDBX_PASSWORD" in result.stderr and "--password-stdin" in result.stderr
    assert not session.SESSION_FILE.exists()


def test_status_without_a_session_is_a_plain_answer_not_a_crash():
    result = CliRunner().invoke(app, ["session", "status"])
    assert result.exit_code == 1  # locked
