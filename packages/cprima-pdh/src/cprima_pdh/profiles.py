"""Profiles: complete variants of a taxonomy, shipped with the package (`data/profiles/<taxonomy>-<name>.toml`).

A profile is named by its taxonomy and its own name, joined: `pdh-default`. It is not an overlay: a vault is checked
against exactly one profile, and profiles are never merged. Inside a profile the taxonomy is dogma.
`--schemas FILE` still loads any single taxonomy file instead.
"""
from __future__ import annotations

import tomllib
from importlib.resources import files

from .models import ProfileInfo
from .schema import DEFAULT_PROFILE, SchemaError, SchemaSet, parse_schemas

DEFAULT = DEFAULT_PROFILE
_DIR = files("cprima_pdh") / "data" / "profiles"


def names() -> list[str]:
    """The full names (file stems) of the packaged profiles."""
    return sorted(p.name[: -len(".toml")] for p in _DIR.iterdir() if p.name.endswith(".toml"))


def load(name: str) -> SchemaSet:
    """The packaged profile with this full name; SchemaError (listing what exists) for an unknown one."""
    if name not in names():
        raise SchemaError(f"unknown profile {name!r} (available: {', '.join(names())})")
    text = (_DIR / f"{name}.toml").read_text(encoding="utf-8")
    raw = tomllib.loads(text)
    missing = [t for t in ("level", "standard", "kind", "advice", "binding") if t not in raw]
    if missing:  # fragments may inherit them, a profile is complete
        raise SchemaError(f"{name}.toml must state its own [{'] and ['.join(missing)}]: a profile is complete")
    sset = parse_schemas(text, f"profile {name}")
    if sset.profile is None or sset.profile.full_name != name:
        raise SchemaError(f"{name}.toml must have a [profile] header whose taxonomy and name give {name!r} "
                          f"(taxonomy-name)")
    return sset


def infos() -> list[ProfileInfo]:
    out = []
    for n in names():
        meta = load(n).profile
        out.append(ProfileInfo(name=meta.full_name, taxonomy=meta.taxonomy, version=meta.version,
                               description=meta.description))
    return out
