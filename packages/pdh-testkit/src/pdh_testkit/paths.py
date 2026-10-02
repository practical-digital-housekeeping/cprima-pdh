"""Locations inside the monorepo that tests read (the taxonomy profiles are the method's source of truth)."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
PROFILES_DIR = REPO_ROOT / "method" / "taxonomy" / "profiles"
PACKAGED_PROFILES_DIR = REPO_ROOT / "packages" / "cprima-pdh" / "src" / "cprima_pdh" / "data" / "profiles"
DEFAULT_PROFILE = "pdh-default"  # the full name: taxonomy `pdh`, profile `default`
TAXONOMY = PROFILES_DIR / f"{DEFAULT_PROFILE}.toml"
TAXONOMY_MD = PROFILES_DIR / f"{DEFAULT_PROFILE}.md"
PACKAGED_TAXONOMY = PACKAGED_PROFILES_DIR / f"{DEFAULT_PROFILE}.toml"
