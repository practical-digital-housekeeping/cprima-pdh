"""`pdh doctor`: setup / file / method in one overview. Never prompts, never opens a locked vault, never shows a value.

The file and method sections run on a real (synthetic) vault file opened by pykeepass.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh import doctor
from cprima_pdh.cli import _common, app
from cprima_pdh.schema import parse_schemas
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

TAXONOMY = parse_schemas("""
[area."Shopping"]
description = "Shops."

[field.serial_number]
protected = false

[field.PIN]
protected = true

[facet.login]
required = ["Title", "UserName", "Password", "URL"]

[schema.website]
facets = ["login"]
""")

PAST = datetime.now(timezone.utc) - timedelta(days=3)
SOON = datetime.now(timezone.utc) + timedelta(days=10)

ENTRIES = [
    Entry("Shop", group="alice/Shopping", username="u", password="PW-SENTINEL", url="https://shop.example",
          custom={"_schema": "website"}),
    Entry("Blog", group="alice/Shopping", username="", password="p", url="http://blog.example",
          custom={"_schema": "website"}),
    Entry("Router", group="alice/Home", password="p", custom={"serial_number": "1", "PIN": "VALUE-SENTINEL",
                                                             "colour": "COLOUR-SENTINEL"}, expires=PAST),
    Entry("Card", group="bob", password="", custom={"_schema": "nope"}, expires=SOON),   # no user name, no URL: not a login
    Entry("Half login", group="bob", username="bob", password="", url="https://half.example.org/"),
    Entry("Loose", password="p"),
]


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", ENTRIES, groups=["alice/Empty"])


def diagnose(db, monkeypatch, *, unlocked=False, taxonomy=lambda: TAXONOMY):
    monkeypatch.setattr(doctor.session, "seconds_left", lambda: 1800 if unlocked else 0)
    monkeypatch.setattr(doctor.session, "load_session", lambda _db: ("x", None) if unlocked else None)
    opener = ((lambda d: pykeepass_open(d, DEFAULT_PASSWORD, None)) if unlocked
              else (lambda _d: pytest.fail("vault opened while locked")))
    return doctor.diagnose(db, taxonomy, "test taxonomy", opener)


def line(report, section, name):
    hits = [c for c in report.checks if c.section == section and c.name == name]
    assert hits, f"no {section}/{name}"
    return hits[0]


# --- setup ---------------------------------------------------------------------------------------

def test_no_vault_is_a_warning_and_skips_file_and_method(monkeypatch):
    rep = diagnose(None, monkeypatch)
    assert line(rep, "setup", "vault").status == "warn" and not rep.failed
    assert line(rep, "file", "vault").status == "skip" and line(rep, "method", "progress").status == "skip"


def test_a_broken_taxonomy_is_reported_not_raised(vault, monkeypatch):
    def broken():
        raise ValueError("bad toml")

    rep = diagnose(vault, monkeypatch, taxonomy=broken)
    assert line(rep, "setup", "taxonomy").status == "fail" and line(rep, "file", "format").status in ("ok", "warn")


# --- file: header, no password -------------------------------------------------------------------

def test_header_without_a_password(vault, monkeypatch):
    fmt = line(diagnose(vault, monkeypatch), "file", "format")
    assert "KDBX 4.0" in fmt.detail and "AES-256" in fmt.detail and "Argon2" in fmt.detail


def test_weak_key_derivation_is_a_warning(vault, monkeypatch):
    # synthetic vaults lower Argon2 on purpose (8 MiB, 1 iteration): exactly what doctor must flag
    assert line(diagnose(vault, monkeypatch), "file", "format").status == "warn"


def test_a_file_that_is_not_a_vault_fails(tmp_path, monkeypatch):
    junk = tmp_path / "x.kdbx"
    junk.write_bytes(b"not a vault at all")
    assert line(diagnose(junk, monkeypatch), "file", "vault").status == "fail"


@pytest.mark.parametrize("header,expected", [
    ({"kdf": "AES-KDF", "rounds": 6_000_000}, False), ({"kdf": "AES-KDF", "rounds": 6000}, True),
    ({"kdf": "Argon2id", "memory": 64 << 20, "iterations": 10, "threads": 2}, False),
    ({"kdf": "Argon2d", "memory": 1 << 20, "iterations": 10, "threads": 2}, True),
])
def test_kdf_strength(header, expected):
    assert doctor._kdf_text(header)[1] is expected


def test_lock_file_and_sync_conflicts_are_warnings(vault, monkeypatch):
    (vault.parent / "v.kdbx.lock").write_bytes(b"")
    (vault.parent / "v.sync-conflict-20261002-101010-ABCDEFG.kdbx").write_bytes(b"")
    rep = diagnose(vault, monkeypatch)
    assert [c.status for c in rep.checks if c.name == "in use"] == ["warn", "warn"]


def test_locked_session_skips_contents_and_method(vault, monkeypatch):
    rep = diagnose(vault, monkeypatch)
    assert line(rep, "setup", "session").status == "warn"
    assert line(rep, "file", "contents").status == "skip" and line(rep, "method", "progress").status == "skip"
    assert not rep.failed


def test_a_sidecar_password_replaces_the_session(vault, monkeypatch):
    (vault.with_suffix(".toml")).write_text(f'password = "{DEFAULT_PASSWORD}"\n', encoding="utf-8")
    monkeypatch.setattr(doctor.session, "seconds_left", lambda: 0)  # locked
    rep = doctor.diagnose(vault, lambda: TAXONOMY, "test taxonomy", lambda d: pykeepass_open(d, DEFAULT_PASSWORD, None))
    session_line = line(rep, "setup", "session")
    assert session_line.status == "ok" and "sidecar v.toml" in session_line.detail
    assert line(rep, "file", "contents").status == "ok" and DEFAULT_PASSWORD not in rep.model_dump_json()


# --- file: contents (unlocked) -------------------------------------------------------------------

def test_contents(vault, monkeypatch):
    rep = diagnose(vault, monkeypatch, unlocked=True)
    contents = line(rep, "file", "contents").detail
    assert "6 entries" in contents and "1 at the root" in contents and "(1 empty)" in contents
    expiry = line(rep, "file", "expiry")
    assert expiry.status == "warn" and "1 expired, 1 within 30 days" in expiry.detail


# --- method --------------------------------------------------------------------------------------

def test_method_axes(vault, monkeypatch):
    rep = diagnose(vault, monkeypatch, unlocked=True)
    assert line(rep, "method", "owners").detail.startswith("2: alice 3, bob 2")
    assert "2 of 6 (33 %) in starter areas" in line(rep, "method", "areas").detail
    types = line(rep, "method", "record types")
    assert types.status == "warn" and "2 of 6 (33 %) typed: website 2" in types.detail and "1 unknown" in types.detail
    vocab = line(rep, "method", "vocabulary")
    assert vocab.status == "warn" and "3 field names: 2 terms" in vocab.detail and "1 unprotected" in vocab.detail
    conf = line(rep, "method", "conformance")
    assert conf.status == "warn" and "ERROR" in conf.detail
    hygiene = line(rep, "method", "hygiene").detail
    # only logins count: "Half login" has a user name and a URL but no password; the card has neither of those
    assert "1 login without a password" in hygiene and "1 http://" in hygiene


def test_record_types_count_types_that_follow_from_the_fields(tmp_path, monkeypatch):
    ruled = parse_schemas("""
[schema.website]
required = ["Title"]
[schema.bank-account]
required = ["Title", "IBAN"]
[[match]]
schema = "bank-account"
has = ["IBAN"]
""")
    path = synthetic_vault(tmp_path / "m.kdbx", [Entry("Written", custom={"_schema": "website"}),
                                                Entry("Derived", custom={"IBAN": "x"}), Entry("Plain")])
    monkeypatch.setattr(doctor.session, "seconds_left", lambda: 1800)
    monkeypatch.setattr(doctor.session, "load_session", lambda _db: ("x", None))
    rep = doctor.diagnose(path, lambda: ruled, "t", lambda d: pykeepass_open(d, DEFAULT_PASSWORD, None))
    types = line(rep, "method", "record types").detail
    assert "2 of 3 (67 %) typed" in types and "1 only by field rules" in types


def test_no_value_ever_appears(vault, monkeypatch):
    out = diagnose(vault, monkeypatch, unlocked=True).model_dump_json()
    for sentinel in ("PW-SENTINEL", "VALUE-SENTINEL", "COLOUR-SENTINEL", DEFAULT_PASSWORD):
        assert sentinel not in out


# --- CLI -----------------------------------------------------------------------------------------

def test_cli_sections_in_text_and_json(vault, monkeypatch):
    monkeypatch.setattr(doctor.session, "seconds_left", lambda: 0)
    monkeypatch.setattr(_common, "open_db", lambda *_a: pytest.fail("doctor must not open a locked vault"))
    text = CliRunner().invoke(app, ["--db", str(vault), "doctor"]).stdout
    assert text.index("setup\n") < text.index("file\n") < text.index("method\n")
    data = json.loads(CliRunner().invoke(app, ["--db", str(vault), "doctor", "-f", "json"]).stdout)
    assert {c["section"] for c in data["checks"]} == {"setup", "file", "method"}


def test_cli_without_vault_warns_and_exits_0():
    result = CliRunner().invoke(app, ["doctor"], env={"KDBX_FILE": ""})
    assert result.exit_code == 0 and "[warn] vault" in result.stdout and "no vault given" in result.stdout
