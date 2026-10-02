"""Profiles: complete, named taxonomies shipped with the package. A vault follows exactly one; they never merge."""
import json

import pytest
from pdh_testkit.paths import PACKAGED_PROFILES_DIR, PROFILES_DIR
from pdh_testkit.runner import pdh_runner

from cprima_pdh import profiles
from cprima_pdh.schema import SchemaError, load_schemas
from cprima_pdh.taxonomy import build

NAMES = sorted(p.stem for p in PROFILES_DIR.glob("*.toml"))


def test_there_is_a_default_profile_named_after_taxonomy_and_profile():
    assert profiles.DEFAULT == "pdh-default" and profiles.DEFAULT in profiles.names()
    meta = profiles.load(profiles.DEFAULT).profile
    assert (meta.taxonomy, meta.name) == ("pdh", "default")


def test_the_packaged_profiles_are_the_sources(tmp_path):
    """The wheel ships a copy of every method/taxonomy/profiles/*.toml; `just taxonomy` refreshes them."""
    assert profiles.names() == NAMES
    for name in NAMES:
        assert (PACKAGED_PROFILES_DIR / f"{name}.toml").read_bytes() == (PROFILES_DIR / f"{name}.toml").read_bytes(), \
            f"packaged {name}.toml is stale: run `just taxonomy`"


@pytest.mark.parametrize("name", NAMES)
def test_every_profile_loads_and_its_file_is_named_taxonomy_dash_profile(name):
    sset = profiles.load(name)
    assert sset.profile is not None and sset.profile.version
    assert sset.profile.full_name == name == f"{sset.profile.taxonomy}-{sset.profile.name}"
    assert sset.schemas and sset.fields and sset.areas
    assert load_schemas(PROFILES_DIR / f"{name}.toml").profile == sset.profile


@pytest.mark.parametrize("name", NAMES)
def test_every_profile_has_a_current_generated_document(name):
    """<name>.md is generated from <name>.toml; this fails when someone changed one but not the other."""
    on_disk = (PROFILES_DIR / f"{name}.md").read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    assert on_disk == build(profiles.load(name)).markdown, f"{name}.md is stale: run `just taxonomy`"


def test_unknown_profile_lists_the_available_ones():
    with pytest.raises(SchemaError, match="available: "):
        profiles.load("nope")


def test_infos_describe_each_profile():
    assert [(i.name, bool(i.version)) for i in profiles.infos()] == [(n, True) for n in NAMES]


# --- the CLI -------------------------------------------------------------------------------------

@pytest.fixture
def run(monkeypatch, tmp_path):
    return pdh_runner(monkeypatch, tmp_path)


def test_method_profiles_lists_them(run):
    out = run([], "method", "profiles", with_db=False).stdout
    assert "pdh-default" in out and profiles.load("pdh-default").profile.version in out


def test_the_short_name_alone_is_not_a_profile(run):
    assert run([], "--profile", "default", "method", "schemas", with_db=False).exit_code == 2


def test_profile_option_selects_one_and_default_is_used_otherwise(run):
    assert run([], "--profile", "pdh-default", "method", "schemas", with_db=False).exit_code == 0
    assert run([], "method", "schemas", with_db=False).exit_code == 0


def test_an_unknown_profile_exits_2(run):
    result = run([], "--profile", "nope", "method", "schemas", with_db=False)
    assert result.exit_code == 2 and "available" in result.stderr


def test_a_schemas_file_overrides_the_profile(monkeypatch, tmp_path):
    custom = pdh_runner(monkeypatch, tmp_path, "[schema.only]\nrequired = ['Title']\n")
    result = custom([], "--profile", "pdh-default", "method", "schemas", "-f", "json", with_db=False)
    assert result.exit_code == 0 and list(json.loads(result.stdout)["schemas"]) == ["only"]
