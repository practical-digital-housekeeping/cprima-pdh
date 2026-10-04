"""Which vault: --db > --vault/PDH_VAULT > KDBX_FILE > config default > unlocked session.

Config files merge, later wins: XDG config < ./pdh.toml < $PDH_CONFIG. Relative paths resolve from the file's folder.
"""
import json
from pathlib import Path

import pytest
from pdh_testkit import synthetic_vault
from typer.testing import CliRunner

from cprima_pdh import config, session
from cprima_pdh.cli import app


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def xdg(monkeypatch, tmp_path):
    d = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(d))
    return d / "cprima-pdh" / "config.toml"


# --- loading and merging -------------------------------------------------------------------------

def test_no_config_files_is_fine(tmp_path):
    cfg = config.load_config(tmp_path)
    assert (cfg.files, cfg.vaults, cfg.default) == ([], {}, None)


def test_relative_paths_resolve_from_the_config_files_folder(xdg):
    write(xdg, '[vaults.a]\npath = "vaults/a.kdbx"\nkey = "a.key"\n')
    ref = config.load_config().vaults["a"]
    assert ref.path == xdg.parent / "vaults" / "a.kdbx" and ref.key == xdg.parent / "a.key"


def test_later_files_override_earlier_ones(xdg, tmp_path, monkeypatch):
    write(xdg, 'default = "a"\n[vaults.a]\npath = "x.kdbx"\n[vaults.b]\npath = "y.kdbx"\n')
    cwd = tmp_path / "work"
    write(cwd / "pdh.toml", 'default = "b"\n[vaults.a]\npath = "local.kdbx"\n')
    env = write(tmp_path / "env.toml", '[vaults.c]\npath = "z.kdbx"\n')
    monkeypatch.setenv("PDH_CONFIG", str(env))
    cfg = config.load_config(cwd)
    assert cfg.files == [xdg, cwd / "pdh.toml", env]
    assert cfg.default == "b" and cfg.vaults["a"].path == cwd / "local.kdbx" and set(cfg.vaults) == {"a", "b", "c"}


@pytest.mark.parametrize("text,fragment", [
    ('surprise = 1\n', "unknown keys"),
    ('[vaults.a]\nkey = "k"\n', "needs `path`"),
    ('[vaults.a]\npath = "p"\ncolour = "x"\n', "needs `path`"),
    ('default = "nope"\n[vaults.a]\npath = "p"\n', "not defined"),
    ('this is = = not toml', None),
])
def test_bad_config_is_an_error(xdg, text, fragment):
    write(xdg, text)
    with pytest.raises(config.ConfigError, match=fragment):
        config.load_config()


# --- the profile key -----------------------------------------------------------------------------

def test_profile_keys_load_at_top_level_and_per_vault(xdg):
    write(xdg, 'profile = "p0"\n[vaults.a]\npath = "a.kdbx"\nprofile = "p1"\n[vaults.b]\npath = "b.kdbx"\n')
    cfg = config.load_config()
    assert cfg.profile == "p0" and cfg.vaults["a"].profile == "p1" and cfg.vaults["b"].profile is None


def test_a_later_file_overrides_the_top_level_profile(xdg, tmp_path):
    write(xdg, 'profile = "p0"\n')
    cwd = tmp_path / "work"
    write(cwd / "pdh.toml", 'profile = "p2"\n')
    assert config.load_config(cwd).profile == "p2"


@pytest.mark.parametrize("text", ['profile = 3\n', 'profile = ""\n', '[vaults.a]\npath = "p"\nprofile = 1\n'])
def test_a_profile_must_be_a_non_empty_string(xdg, text):
    write(xdg, text)
    with pytest.raises(config.ConfigError, match="profile"):
        config.load_config()


PCFG = config.Config(
    vaults={"a": config.VaultRef("a", Path("/cfg/a.kdbx"), None, Path("/cfg/c.toml"), profile="p-vault"),
            "b": config.VaultRef("b", Path("/cfg/b.kdbx"), None, Path("/cfg/c.toml"))},
    profile="p-config", profile_origin=Path("/cfg/c.toml"))


@pytest.mark.parametrize("vault_name,cli_db,expected,source_start", [
    ("a", None, "p-vault", "vault 'a'"),        # a vault's own profile wins over the config's
    ("b", None, "p-config", "config"),          # else the config's top-level profile
    (None, Path("/x.kdbx"), "p-config", "config"),  # also for a vault named on the command line
])
def test_profile_precedence_in_the_config(vault_name, cli_db, expected, source_start):
    r = config.resolve_vault(cli_db, False, None, vault_name, PCFG, None)
    assert r.profile == expected and r.profile_source.startswith(source_start)


def test_no_profile_anywhere_leaves_it_to_the_default():
    r = config.resolve_vault(Path("/x.kdbx"), False, None, None, config.Config(), None)
    assert (r.profile, r.profile_source) == (None, "")


# --- resolution order ----------------------------------------------------------------------------

CFG = config.Config(vaults={"a": config.VaultRef("a", Path("/cfg/a.kdbx"), Path("/cfg/a.key"), Path("/cfg/c.toml")),
                            "b": config.VaultRef("b", Path("/cfg/b.kdbx"), None, Path("/cfg/c.toml"))},
                    default="b", default_origin=Path("/cfg/c.toml"))


@pytest.mark.parametrize("args,expected_db,source_start", [
    (dict(cli_db=Path("/cli.kdbx"), db_from_env=False, vault_name="a"), "/cli.kdbx", "--db"),
    (dict(cli_db=Path("/env.kdbx"), db_from_env=True, vault_name="a"), "/cfg/a.kdbx", "vault 'a'"),
    (dict(cli_db=Path("/env.kdbx"), db_from_env=True, vault_name=None), "/env.kdbx", "KDBX_FILE"),
    (dict(cli_db=None, db_from_env=False, vault_name=None), "/cfg/b.kdbx", "default vault 'b'"),
])
def test_precedence(args, expected_db, source_start):
    r = config.resolve_vault(cli_key=None, cfg=CFG, session_db=Path("/session.kdbx"), **args)
    assert r.db == Path(expected_db) and r.source.startswith(source_start)


def test_a_single_configured_vault_is_the_default():
    cfg = config.Config(vaults={"only": CFG.vaults["a"]})
    assert config.resolve_vault(None, False, None, None, cfg, None).db == Path("/cfg/a.kdbx")


def test_the_unlocked_session_is_the_last_resort():
    r = config.resolve_vault(None, False, None, None, config.Config(), Path("/session.kdbx"))
    assert (r.db, r.source) == (Path("/session.kdbx"), "the unlocked session")


def test_nothing_anywhere_means_no_vault():
    assert config.resolve_vault(None, False, None, None, config.Config(), None).db is None


def test_an_explicit_key_beats_the_configured_one():
    r = config.resolve_vault(None, False, Path("/my.key"), "a", CFG, None)
    assert r.key == Path("/my.key")


def test_unknown_vault_name_lists_the_known_ones():
    with pytest.raises(config.ConfigError, match="known: a, b"):
        config.resolve_vault(None, False, None, "zzz", CFG, None)


# --- through the CLI -----------------------------------------------------------------------------

def test_doctor_uses_the_current_folders_config_and_says_so(tmp_path, monkeypatch):
    work = tmp_path / "work"
    synthetic_vault(work / "fixtures" / "dev.kdbx")
    write(work / "pdh.toml", '[vaults.dev]\npath = "fixtures/dev.kdbx"\n')
    monkeypatch.chdir(work)
    monkeypatch.setattr(session, "seconds_left", lambda: 0)
    data = json.loads(CliRunner().invoke(app, ["doctor", "-f", "json"]).stdout)
    vault = [c for c in data["checks"] if c["section"] == "setup" and c["name"] == "vault"][0]
    assert vault["status"] == "ok" and "default vault 'dev'" in vault["detail"]
    assert any(c["section"] == "file" and c["name"] == "format" for c in data["checks"])


def test_pdh_vault_env_picks_a_named_vault(tmp_path, monkeypatch):
    work = tmp_path / "work"
    synthetic_vault(work / "one.kdbx")
    synthetic_vault(work / "two.kdbx")
    write(work / "pdh.toml", '[vaults.one]\npath = "one.kdbx"\n[vaults.two]\npath = "two.kdbx"\n')
    monkeypatch.chdir(work)
    monkeypatch.setattr(session, "seconds_left", lambda: 0)
    out = CliRunner().invoke(app, ["doctor"], env={"PDH_VAULT": "two"}).stdout
    assert "two.kdbx" in out and "vault 'two'" in out


def test_the_config_profile_is_used_and_the_command_line_wins(tmp_path, monkeypatch):
    write(tmp_path / "pdh.toml", 'profile = "nope"\n')
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    broken = runner.invoke(app, ["method", "schemas"])  # the config names a profile that does not exist
    assert broken.exit_code == 2 and "unknown profile 'nope'" in broken.stderr
    assert runner.invoke(app, ["--profile", "pdh-default", "method", "schemas"]).exit_code == 0
    assert runner.invoke(app, ["method", "schemas"], env={"PDH_PROFILE": "pdh-default"}).exit_code == 0


def test_a_vaults_own_profile_beats_the_config_profile(tmp_path, monkeypatch):
    synthetic_vault(tmp_path / "v.kdbx")
    write(tmp_path / "pdh.toml", 'profile = "nope"\n[vaults.v]\npath = "v.kdbx"\nprofile = "pdh-default"\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(session, "seconds_left", lambda: 0)
    out = CliRunner().invoke(app, ["doctor"]).stdout
    assert "[ok  ] taxonomy" in out and "profile 'pdh-default'" in out and "from vault 'v'" in out


def test_doctor_names_where_the_profile_came_from(tmp_path, monkeypatch):
    write(tmp_path / "pdh.toml", 'profile = "pdh-default"\n')
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(app, ["doctor"]).stdout
    assert "profile 'pdh-default' v0.1 (from config" in out


def test_a_broken_config_exits_2(tmp_path, monkeypatch):
    write(tmp_path / "pdh.toml", "surprise = 1\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 2 and "config error" in result.stderr
