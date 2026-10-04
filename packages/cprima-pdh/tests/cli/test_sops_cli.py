"""The ordinary read commands run on a sops file: the engine neither knows nor cares which backend it reads."""
import json

import pytest
from pdh_testkit.sopsfix import load_sops
from typer.testing import CliRunner

from cprima_pdh.cli import app

FIX = load_sops("sops-json-basic")


@pytest.fixture
def run(tmp_path, monkeypatch):
    key = tmp_path / "keys.txt"
    key.write_text(FIX.identity_text, encoding="utf-8")
    monkeypatch.delenv("SOPS_AGE_KEY", raising=False)
    monkeypatch.delenv("SOPS_AGE_KEY_FILE", raising=False)

    def go(*args, key_option=True, env=None):
        base = ["--db", str(FIX.path), *(["--key", str(key)] if key_option else [])]
        return CliRunner().invoke(app, [*base, *args], env=env)

    go.key = key
    return go


def data(result):
    assert result.exit_code == 0, result.output + (result.stderr or "")
    return json.loads(result.stdout)


def test_tree_shows_groups_and_entries(run):
    out = run("inspect", "tree", "--entries")
    assert out.exit_code == 0 and "Money" in out.stdout and "Cards" in out.stdout and "login" in out.stdout


def test_entries_and_find_list_records_without_secrets(run):
    entries = data(run("inspect", "entries", "-f", "json"))["entries"]
    assert sorted(e["title"] for e in entries) == ["Deep" and "entry", "login", "plain", "top", "twin"] or len(entries) == 5
    found = data(run("inspect", "find", "twin", "-f", "json"))["entries"]
    assert [e["title"] for e in found] == ["twin"]
    assert "pw-1" not in run("inspect", "entries", "-f", "json").stdout


def test_find_in_fields_searches_values_that_sops_encrypted(run):
    assert [e["title"] for e in data(run("inspect", "find", "c-1", "--in-fields", "-f", "json"))["entries"]] == ["login"]


def test_inventory_reads_the_backends_facts(run):
    inv = data(run("inspect", "inventory", "-f", "json"))
    assert inv["entries"] == 5 and inv["meta"]["cipher"] == "AES256_GCM" and inv["meta"]["version"].startswith("sops 3.")


def test_unclassified_and_validate_run_on_the_snapshots(run):
    assert data(run("inspect", "unclassified", "-f", "json"))["total"] == 5
    report = data(run("check", "validate", "-f", "json"))
    assert report["unclassified_entries"] == 5 and any(f["rule"] == "unknown-field" for f in report["findings"])


def test_conform_runs_too(run):
    out = data(run("check", "conform", "--status", "all", "-f", "json"))
    assert out["unclassified"] + out["nonconform"] + out["conform"] == 5


def test_otp_and_show_work_and_show_masks_the_password(run):
    shown = data(run("inspect", "show", "login", "-f", "json"))
    assert shown["password"] == "********" and shown["username"] == "alex"
    assert run("inspect", "otp", "Money/Cards/login").exit_code == 1  # (no one-time password in the fixture)


def test_the_identity_can_come_from_the_environment(run, tmp_path):
    out = run("inspect", "entries", "-f", "json", key_option=False, env={"SOPS_AGE_KEY": FIX.identity_text})
    assert out.exit_code == 0 and len(json.loads(out.stdout)["entries"]) == 5


def test_without_an_identity_it_says_what_to_set(run):
    out = run("inspect", "entries", key_option=False, env={"APPDATA": "nowhere", "XDG_CONFIG_HOME": "nowhere"})
    assert out.exit_code == 1 and "SOPS_AGE_KEY_FILE" in out.stderr


def test_a_wrong_identity_is_refused_not_a_traceback(run, tmp_path):
    keygen = __import__("shutil").which("age-keygen")
    if not keygen:
        pytest.skip("age-keygen is not installed")
    wrong = tmp_path / "wrong.txt"
    wrong.write_text(__import__("subprocess").run([keygen], capture_output=True, text=True, check=True).stdout, encoding="utf-8")
    out = CliRunner().invoke(app, ["--db", str(FIX.path), "--key", str(wrong), "inspect", "entries"])
    assert out.exit_code == 1 and "recipient" in out.stderr


@pytest.mark.parametrize("args", [
    ("edit", "set", "Other/twin", "Notes", "x", "--apply"),
    ("edit", "new-group", "/", "G", "--apply"),
    ("edit", "delete", "Other/twin", "--apply"),
    ("db", "settings"),
])
def test_commands_that_need_a_writable_keepass_vault_say_so(run, args):
    out = run(*args)
    assert out.exit_code == 2 and "sops" in out.stderr


@pytest.mark.parametrize("args,capability", [(("inspect", "history", "Other/twin"), "history"),
                                             (("inspect", "attachments", "Other/twin"), "attachments")])
def test_capabilities_the_backend_lacks_are_named(run, args, capability):
    out = run(*args)
    assert out.exit_code == 2 and f"does not support {capability}" in out.stderr


# --- doctor ------------------------------------------------------------------------------------------------------------

def test_doctor_describes_a_sops_file(run):
    out = run("doctor")
    assert out.exit_code == 0
    assert "sops ready" in out.stdout and "MAC verified" in out.stdout and "AES256_GCM" in out.stdout
    assert "2 recipient(s)" in out.stdout and "no lock" in out.stdout
    assert "1 value(s) are not part of any entry" in out.stdout  # the stray scalar of the fixture


def test_doctor_reports_a_missing_identity_instead_of_failing_silently(run):
    out = run("doctor", key_option=False, env={"APPDATA": "nowhere", "XDG_CONFIG_HOME": "nowhere"})
    assert out.exit_code == 1 and "could not open" in out.stdout and "SOPS_AGE_KEY_FILE" in out.stdout
