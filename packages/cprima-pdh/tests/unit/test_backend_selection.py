"""Which backend works on a file: the explicit choices in their order, always checked against what the file really is."""
import pytest
from pdh_testkit import Entry, synthetic_vault
from pdh_testkit.sopsfix import load_sops
from typer.testing import CliRunner

from cprima_pdh import backends
from cprima_pdh.cli import app


@pytest.fixture
def kdbx(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G")])


@pytest.fixture
def sops():
    return load_sops("sops-json-basic").path


@pytest.fixture
def text(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some text, not a vault\n", encoding="utf-8")
    return path


@pytest.fixture
def empty(tmp_path):
    path = tmp_path / "new.kdbx"
    path.write_bytes(b"")
    return path


def test_the_content_decides_when_nothing_is_chosen(kdbx, sops):
    assert backends.select(kdbx) == backends.Selection("kdbx", "file content")
    assert backends.select(sops) == backends.Selection("sops", "file content")


def test_the_content_beats_the_extension(tmp_path, kdbx):
    renamed = tmp_path / "vault.json"
    renamed.write_bytes(kdbx.read_bytes())
    assert backends.select(renamed).name == "kdbx"


def test_the_first_explicit_choice_wins(kdbx):
    chosen = [("kdbx", "--backend"), ("sops", "PDH_BACKEND"), ("sops", 'vault "x" in pdh.toml')]
    assert backends.select(kdbx, chosen) == backends.Selection("kdbx", "--backend")


@pytest.mark.parametrize("level", ["--backend", "PDH_BACKEND", 'vault "x" in pdh.toml', "config default in pdh.toml"])
def test_every_level_is_honoured_when_it_is_the_only_one(sops, level):
    assert backends.select(sops, [("sops", level)]) == backends.Selection("sops", level)


def test_a_choice_the_file_contradicts_is_refused_with_both_sides_named(kdbx):
    with pytest.raises(backends.BackendMismatch, match=r"v\.kdbx is a kdbx file, not sops \(chosen by PDH_BACKEND\)"):
        backends.select(kdbx, [("sops", "PDH_BACKEND")])


def test_an_explicit_choice_is_accepted_for_a_file_no_backend_recognises(text):
    assert backends.select(text, [("kdbx", "--backend")]).name == "kdbx"


def test_a_file_nothing_recognises_is_an_error_that_names_the_way_out(text):
    with pytest.raises(backends.BackendUndetected, match=r"cannot tell what kind of vault 'notes\.txt' is \(tried: kdbx, sops\).*--backend"):
        backends.select(text)


def test_an_empty_file_gets_the_built_in_default(empty):
    assert backends.select(empty) == backends.Selection("kdbx", "built-in default (the file is empty)")


def test_a_backend_that_does_not_exist_is_named(kdbx):
    with pytest.raises(backends.BackendMissing, match=r'no backend "bitwarden" \(chosen by --backend\); known: kdbx, sops'):
        backends.select(kdbx, [("bitwarden", "--backend")])


def test_the_command_line_says_what_it_could_not_tell(text):
    result = CliRunner().invoke(app, ["--db", str(text), "inspect", "entries"])
    assert result.exit_code == 2 and "cannot tell what kind of vault" in result.stderr and "--backend" in result.stderr


# --- the command line: --backend and PDH_BACKEND ----------------------------------------------------------------------

def run(db, *args, env=None):
    return CliRunner().invoke(app, ["--db", str(db), *args], env=env)


def test_the_flag_is_checked_against_the_file(kdbx):
    result = CliRunner().invoke(app, ["--backend", "sops", "--db", str(kdbx), "inspect", "entries"])
    assert result.exit_code == 2 and "v.kdbx is a kdbx file, not sops (chosen by --backend)" in result.stderr


def test_the_environment_is_checked_against_the_file(kdbx):
    result = run(kdbx, "inspect", "entries", env={"PDH_BACKEND": "sops"})
    assert result.exit_code == 2 and "(chosen by PDH_BACKEND)" in result.stderr


def test_the_flag_beats_the_environment(kdbx):
    result = CliRunner().invoke(app, ["--backend", "kdbx", "--db", str(kdbx), "inspect", "tree"], env={"PDH_BACKEND": "sops"})
    assert "not sops" not in (result.stderr or "")


def test_doctor_names_where_the_backend_choice_came_from(kdbx):
    result = CliRunner().invoke(app, ["--backend", "kdbx", "--db", str(kdbx), "doctor"])
    assert "kdbx ready (from --backend)" in result.stdout
    assert "kdbx ready (from file content)" in run(kdbx, "doctor").stdout


# --- the config: the vault's own `backend`, then the config's `backend` --------------------------------------------------

@pytest.fixture
def configured(tmp_path, kdbx):
    """A config file naming `kdbx` as a vault, with `backend` settings the tests choose."""
    def make(top: str = "", vault: str = "") -> dict[str, str]:
        path = tmp_path / "pdh.toml"
        path.write_text(f'{top}\n[vaults.main]\npath = "{kdbx.as_posix()}"\n{vault}\n', encoding="utf-8")
        return {"PDH_CONFIG": str(path), "XDG_CONFIG_HOME": str(tmp_path / "none")}

    return make


def inspect(env, *args):
    return CliRunner().invoke(app, [*args, "inspect", "entries"], env=env)


def test_the_configs_backend_is_checked_against_the_file(configured):
    result = inspect(configured(top='backend = "sops"'), "--vault", "main")
    assert result.exit_code == 2 and "v.kdbx is a kdbx file, not sops (chosen by config " in result.stderr


def test_the_vaults_own_backend_beats_the_configs(configured, opens_with_the_test_password):
    result = inspect(configured(top='backend = "sops"', vault='backend = "kdbx"'), "--vault", "main")
    assert result.exit_code == 0, result.stderr


def test_the_vaults_own_backend_is_named_in_the_refusal(configured):
    result = inspect(configured(vault='backend = "sops"'), "--vault", "main")
    assert result.exit_code == 2 and "(chosen by vault 'main' in " in result.stderr


def test_the_flag_beats_the_vaults_own_backend(configured, opens_with_the_test_password):
    result = inspect(configured(vault='backend = "sops"'), "--backend", "kdbx", "--vault", "main")
    assert result.exit_code == 0, result.stderr


def test_the_configs_backend_applies_to_a_vault_given_with_db(configured, kdbx):
    result = inspect(configured(top='backend = "sops"'), "--db", str(kdbx))
    assert result.exit_code == 2 and "not sops (chosen by config " in result.stderr


@pytest.mark.parametrize("line", ['backend = ""', "backend = 3"])
def test_a_backend_in_the_config_must_be_a_name(configured, line):
    result = inspect(configured(top=line), "--vault", "main")
    assert result.exit_code == 2 and "backend must be a non-empty string" in result.stderr


# --- `pdh backends` ------------------------------------------------------------------------------------------------------

def test_backends_lists_how_each_is_recognised_and_what_it_can_do():
    result = CliRunner().invoke(app, ["backends", "-f", "json"])
    rows = {b["name"]: b for b in __import__("json").loads(result.stdout)["backends"]}
    assert set(rows) >= {"kdbx", "sops"}
    assert "signature" in rows["kdbx"]["detection"] and "sops" in rows["sops"]["detection"]
    assert "history" in rows["kdbx"]["capabilities"] and "history" not in rows["sops"]["capabilities"]
    assert "write" in rows["kdbx"]["capabilities"] and "write" not in rows["sops"]["capabilities"]


def test_backends_text_shows_the_same():
    out = CliRunner().invoke(app, ["backends"]).stdout
    assert "recognised by:" in out and "can:" in out
