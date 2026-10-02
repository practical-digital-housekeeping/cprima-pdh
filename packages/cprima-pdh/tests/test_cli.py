"""CLI wiring through Typer's test runner. The vault is mocked, so there is no file or key derivation."""
import json

import pytest
from pdh_testkit.runner import pdh_runner
from pdh_testkit.stubs import E

TOML = """
[facet.login]
required = ["Title", "UserName", "Password", "URL"]

[schema.website]
facets = ["login"]

[schema.vault]
protected = ["token"]
"""


@pytest.fixture
def run(monkeypatch, tmp_path):
    return pdh_runner(monkeypatch, tmp_path, TOML)


def test_unclassified_counts_per_group_and_lists_entries(run):
    entries = [E(title="a", schema="website", group="Money"), E(title="b", group="Money"), E(title="c", group="Fun")]
    result = run(entries, "inspect", "unclassified", "--entries", "-f", "json")
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["total"] == 2
    assert data["per_group"] == {"Money": 1, "Fun": 1}
    assert data["entries"] == ["Fun/c", "Money/b"]


def test_validate_exits_1_when_there_are_findings(run):
    result = run([E(schema="website", username="")], "check", "validate", "--summary")
    assert result.exit_code == 1
    assert "required:UserName" in result.stdout


def test_validate_exits_0_when_everything_conforms(run):
    result = run([E(schema="website")], "check", "validate")
    assert result.exit_code == 0


def test_validate_json_is_machine_readable(run):
    result = run([E(schema="website, nope")], "check", "validate", "-f", "json")
    data = json.loads(result.stdout)
    assert [f["rule"] for f in data["findings"]] == ["schema:unknown"]


def test_read_never_prints_protected_values(run):
    secret = "TOPSECRET-123"
    e = E(schema="vault", custom={"token": secret}, protected=("token",))
    result = run([e], "inspect", "read")
    assert result.exit_code == 0
    assert "(protected)" in result.stdout
    assert secret not in result.stdout


def test_broken_schema_file_exits_2(run, tmp_path):
    (tmp_path / "schemas.toml").write_text("[schema.a]\ngroups = ['x']\n", encoding="utf-8")
    result = run([E()], "check", "validate")
    assert result.exit_code == 2


def test_method_commands_need_no_vault(run):
    result = run([], "method", "schemas", with_db=False)
    assert result.exit_code == 0
    assert "website" in result.stdout


def test_vault_commands_without_a_vault_say_so(run):
    result = run([], "check", "validate", with_db=False)
    assert result.exit_code == 2


def test_check_alone_runs_conform(run):
    result = run([E(title="ok", schema="website"), E(title="bad", schema="website", username="")], "check")
    assert result.exit_code == 0 and "Area/bad" in result.stdout and "Area/ok" not in result.stdout


def test_packaged_taxonomy_is_the_default(monkeypatch, tmp_path):
    go = pdh_runner(monkeypatch, tmp_path)  # no --schemas
    result = go([], "method", "schemas", with_db=False)
    assert result.exit_code == 0 and "wifi-access-point" in result.stdout


def test_command_groups_are_the_public_surface(run):
    out = run([], "--help", with_db=False).stdout
    for group in ("session", "inspect", "check", "edit", "method", "backends"):
        assert group in out
