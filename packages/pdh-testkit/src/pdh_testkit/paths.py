"""Locations inside the monorepo that tests read (the taxonomy is the method's source of truth)."""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
TAXONOMY = REPO_ROOT / "method" / "taxonomy" / "schemas.toml"
TAXONOMY_MD = REPO_ROOT / "method" / "taxonomy" / "TAXONOMY.md"
PACKAGED_TAXONOMY = REPO_ROOT / "packages" / "cprima-pdh" / "src" / "cprima_pdh" / "data" / "schemas.toml"
