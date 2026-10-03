"""The sops+age backend (read-only): a sops JSON file read as a vault.

Fixture: `sops-json-basic.json`, made with the real sops binary, encrypted to two age recipients; the sidecar holds the
throwaway identity of the first. Tampering tests change the file in memory and expect it to be refused, as sops itself would.
"""
import copy
import json
import os
import shutil
import subprocess
from datetime import timezone

import pytest
from pdh_testkit.sopsfix import load_sops

from cprima_pdh import profiles
from cprima_pdh.backends import age
from cprima_pdh.backends.sops import Backend, SopsVault, default_identities
from cprima_pdh.sopsfmt import SopsError, open_document
from cprima_pdh.validation import validate_entries
from cprima_pdh.vault import Field, Unsupported, require

FIX = load_sops("sops-json-basic")
IDS = age.identities_from_text(FIX.identity_text)


@pytest.fixture
def vault():
    return SopsVault.open(FIX.path, IDS)


def by_path(vault):
    return {e.path: e for e in vault.entries()}


# --- reading ----------------------------------------------------------------------------------------------------------

def test_entries_are_the_mappings_of_scalars(vault):
    assert sorted(by_path(vault)) == ["//top", "Archive/Old/Deep/entry", "Money/Cards/login", "Money/plain", "Other/twin"]


def test_standard_fields_tags_and_custom_fields_with_protection(vault):
    e = by_path(vault)["Money/Cards/login"]
    assert (e.username, e.password, e.url, e.notes) == ("alex", "pw-1", "https://example.org", "n")
    assert list(e.tags) == ["a", "b"]
    assert e.fields == {"customer_no": Field("C-1", True), "token": Field("t", True),
                        "visible_unencrypted": Field("public", False)}  # sops encrypted all but the _unencrypted one
    assert {"UserName", "Password", "URL", "Notes"} <= e.protected_standard


def test_group_paths_and_the_root(vault):
    assert {g.path for g in vault.groups()} == {"/", "Money", "Money/Cards", "Other", "Archive", "Archive/Old",
                                                "Archive/Old/Deep"}
    assert by_path(vault)["//top"].group_path == "/"
    assert by_path(vault)["Archive/Old/Deep/entry"].group_path == "Archive/Old/Deep"


def test_what_is_not_part_of_an_entry_is_counted_not_lost(vault):
    assert vault.unmapped == 1 and vault.info().extra["unmapped values"] == "1"  # the stray top-level scalar


def test_the_time_is_the_files_lastmodified_and_there_is_no_other(vault):
    e = by_path(vault)["Other/twin"]
    assert e.mtime == e.atime and e.mtime.tzinfo is not None and e.mtime.astimezone(timezone.utc).year >= 2026
    assert e.ctime is None and not e.expires and not e.in_bin


def test_ids_are_stable_and_unique(vault):
    again = SopsVault.open(FIX.path, IDS)
    assert [e.id for e in vault.entries()] == [e.id for e in again.entries()]
    assert len({e.id for e in vault.entries()}) == 5 and len({g.id for g in vault.groups()}) == 7


def test_values_equal_what_the_real_sops_decrypts(vault):
    assert vault.document.tree == FIX.plain  # the typed plaintext tree is exactly the original document


def test_info_and_capabilities(vault):
    info = vault.info()
    assert info.backend == "sops" and info.format.startswith("sops 3.") and info.format.endswith("json")
    assert info.cipher == "AES256_GCM" and info.extra["recipients"] == "2" and info.extra["mac"] == "verified"
    assert vault.capabilities == {"fields", "groups", "protected", "tags", "times", "uuid"}
    require(vault, "protected")
    for missing in ("history", "attachments", "recycle_bin", "write", "expiry"):
        with pytest.raises(Unsupported, match=f"does not support {missing}"):
            require(vault, missing)


def test_find_entry(vault):
    assert vault.find_entry("Other/twin").username == "u2"
    with pytest.raises(KeyError):
        vault.find_entry("Other/nope")


def test_the_engine_validates_a_sops_vault_like_any_other(vault):
    report = validate_entries(vault.entries(), profiles.load("pdh-default"))
    assert report.unclassified_entries == 5  # no entry names a record type
    assert any(f.rule == "unknown-field" for f in report.findings)  # `customer_no` etc. are not all vocabulary terms


# --- refusing what is not right ------------------------------------------------------------------------------------------

def test_an_identity_that_is_not_a_recipient_is_refused():
    exe = shutil.which("age-keygen")
    if not exe:
        pytest.skip("age-keygen is not installed")
    other = age.identities_from_text(subprocess.run([exe], capture_output=True, text=True, check=True).stdout)
    with pytest.raises(SopsError, match="none of the given"):
        SopsVault.open(FIX.path, other)


def tampered(change):
    doc = copy.deepcopy(FIX.document())
    change(doc)
    return doc


@pytest.mark.parametrize("change", [
    lambda d: d["Other"]["twin"].__setitem__("Password", d["Other"]["twin"]["UserName"]),  # a ciphertext moved to another key
    lambda d: d["sops"].__setitem__("lastmodified", "2020-01-01T00:00:00Z"),
    lambda d: d["Other"]["twin"].pop("Password"),
    lambda d: d["Money"]["Cards"]["login"].__setitem__("visible_unencrypted", "tampered"),
    lambda d: d["sops"].pop("mac"),
], ids=["moved ciphertext", "lastmodified", "removed key", "changed plaintext value", "no mac"])
def test_an_altered_file_is_refused(change):
    with pytest.raises(SopsError):
        open_document(tampered(change), IDS)


def test_reordered_keys_are_refused():
    doc = copy.deepcopy(FIX.document())
    doc["Other"]["twin"] = dict(reversed(list(doc["Other"]["twin"].items())))
    with pytest.raises(SopsError, match="MAC"):
        open_document(doc, IDS)


def test_yaml_is_not_supported_yet(tmp_path):
    f = tmp_path / "x.yaml"
    f.write_text("sops: {}\n", encoding="utf-8")
    with pytest.raises(SopsError, match="YAML"):
        SopsVault.open(f, IDS)


def test_a_json_file_that_is_not_sops_is_refused(tmp_path):
    f = tmp_path / "x.json"
    f.write_text('{"a": 1}', encoding="utf-8")
    with pytest.raises(SopsError, match="not a sops file"):
        SopsVault.open(f, IDS)


def test_default_identities_come_from_the_environment(monkeypatch, tmp_path):
    key = tmp_path / "keys.txt"
    key.write_text(FIX.identity_text, encoding="utf-8")
    monkeypatch.delenv("SOPS_AGE_KEY", raising=False)
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key))
    assert default_identities() == IDS
    monkeypatch.setenv("SOPS_AGE_KEY", FIX.identity_text)
    assert default_identities() == IDS
    monkeypatch.delenv("SOPS_AGE_KEY")
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(tmp_path / "nope"))
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with pytest.raises(SopsError, match="no age identity"):
        default_identities()


def test_the_backend_reports_its_dependency():
    assert Backend.name == "sops" and Backend.missing_dependencies() == []


# --- age and bech32 --------------------------------------------------------------------------------------------------------

def test_bech32_checks_its_checksum():
    line = [ln for ln in FIX.identity_text.splitlines() if ln.startswith("AGE-SECRET-KEY-")][0]
    hrp, data = age.bech32_decode(line)
    assert hrp == "age-secret-key-" and len(data) == 32
    bad = line[:-1] + ("Q" if line[-1] != "Q" else "P")
    with pytest.raises(age.AgeError):
        age.bech32_decode(bad)


def test_only_x25519_identities_are_accepted():
    with pytest.raises(age.AgeError):
        age.identities_from_text("# nothing here\n")


# --- the real tools as a checker (opt in: just test-client) --------------------------------------------------------------

@pytest.mark.client
def test_real_sops_and_age_produce_files_we_read_identically(tmp_path):
    sops, keygen = shutil.which("sops"), shutil.which("age-keygen")
    if not (sops and keygen):
        pytest.skip("sops and age-keygen are not installed")
    key = tmp_path / "k.txt"
    key.write_text(subprocess.run([keygen], capture_output=True, text=True, check=True).stdout, encoding="utf-8")
    recipient = next(w for w in key.read_text().split() if w.startswith("age1"))
    plain = tmp_path / "p.json"
    plain.write_text(json.dumps(FIX.plain), encoding="utf-8")
    enc = tmp_path / "e.json"
    enc.write_text(subprocess.run([sops, "--encrypt", "--age", recipient, "--unencrypted-suffix", "_unencrypted", str(plain)],
                                  capture_output=True, text=True, check=True).stdout, encoding="utf-8")
    ours = SopsVault.open(enc, age.load_identities(key))
    real = json.loads(subprocess.run([sops, "--decrypt", str(enc)], capture_output=True, text=True, check=True,
                                     env={**os.environ, "SOPS_AGE_KEY_FILE": str(key)}).stdout)
    assert ours.document.tree == real == FIX.plain
    assert sorted(by_path(ours)) == sorted(by_path(SopsVault.open(FIX.path, IDS)))


@pytest.mark.client
def test_real_sops_refuses_the_files_we_refuse(tmp_path):
    sops = shutil.which("sops")
    if not sops:
        pytest.skip("sops is not installed")
    key = tmp_path / "k.txt"
    key.write_text(FIX.identity_text, encoding="utf-8")
    bad = tmp_path / "bad.json"
    doc = FIX.document()
    doc["sops"]["lastmodified"] = "2020-01-01T00:00:00Z"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    result = subprocess.run([sops, "--decrypt", str(bad)], capture_output=True, text=True,
                            env={**os.environ, "SOPS_AGE_KEY_FILE": str(key)})
    assert result.returncode != 0 and "MAC" in result.stderr
    with pytest.raises(SopsError, match="MAC"):
        open_document(doc, IDS)
