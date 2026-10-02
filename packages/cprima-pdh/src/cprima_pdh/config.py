"""Which vault to work on, and where that choice came from.

Config files (TOML) are merged; a later one overrides an earlier one:
    1. $XDG_CONFIG_HOME/cprima-pdh/config.toml   (default ~/.config/cprima-pdh/config.toml)
    2. ./pdh.toml                                 (current folder)
    3. the file named by $PDH_CONFIG

    default = "<name>"            # optional; with a single vault it is the default
    profile = "<profile>"         # optional; the taxonomy profile for every vault (see `pdh method profiles`)
    [vaults.<name>]
    path = "relative/or/absolute.kdbx"   # relative to the config file's folder
    key = "optional/key/file"
    profile = "<profile>"         # optional; this vault follows this profile

Vault resolution, first match wins:
    --db  >  --vault NAME / PDH_VAULT  >  KDBX_FILE  >  the configs' default  >  the vault of the unlocked session
Profile resolution, first match wins:
    --profile / PDH_PROFILE  >  the vault's own `profile`  >  the config's top-level `profile`  >  `pdh-default`
(a profile is named by its full name, taxonomy and name joined: `pdh-default`)
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class VaultRef:
    name: str
    path: Path
    key: Path | None
    origin: Path  # the config file that defines it
    profile: str | None = None


@dataclass
class Config:
    files: list[Path] = field(default_factory=list)  # the files that were found, lowest priority first
    vaults: dict[str, VaultRef] = field(default_factory=dict)
    default: str | None = None
    default_origin: Path | None = None
    profile: str | None = None
    profile_origin: Path | None = None


def config_files(cwd: Path | None = None) -> list[Path]:
    """Existing config files, lowest priority first."""
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    candidates = [xdg / "cprima-pdh" / "config.toml", (cwd or Path.cwd()) / "pdh.toml"]
    if os.environ.get("PDH_CONFIG"):
        candidates.append(Path(os.environ["PDH_CONFIG"]))
    out: list[Path] = []
    for p in candidates:
        if p.is_file() and p.resolve() not in [q.resolve() for q in out]:
            out.append(p)
    return out


def _profile_name(value, path: Path, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{path}: {what} must be a non-empty string")
    return value.strip()


def load_config(cwd: Path | None = None) -> Config:
    cfg = Config()
    for path in config_files(cwd):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"{path}: {exc}") from exc
        unknown = set(data) - {"default", "vaults", "profile"}
        if unknown:
            raise ConfigError(f"{path}: unknown keys {sorted(unknown)}")
        for name, v in (data.get("vaults") or {}).items():
            if not isinstance(v, dict) or "path" not in v or set(v) - {"path", "key", "profile"}:
                raise ConfigError(f"{path}: [vaults.{name}] needs `path` (and optionally `key`, `profile`) only")
            base = path.parent
            key = (base / v["key"]) if v.get("key") else None
            cfg.vaults[name] = VaultRef(name, (base / v["path"]), key, path,
                                        _profile_name(v.get("profile"), path, f"[vaults.{name}] profile"))
        if "default" in data:
            cfg.default, cfg.default_origin = str(data["default"]), path
        if "profile" in data:
            cfg.profile, cfg.profile_origin = _profile_name(data["profile"], path, "profile"), path
        cfg.files.append(path)
    if cfg.default is not None and cfg.default not in cfg.vaults:
        raise ConfigError(f"{cfg.default_origin}: default vault {cfg.default!r} is not defined")
    return cfg


@dataclass(frozen=True)
class Resolved:
    db: Path | None
    key: Path | None
    source: str  # human-readable: where the vault came from
    profile: str | None = None  # from the config (the vault's own, else the top level); None = left to the default
    profile_source: str = ""


def _pick_vault(cli_db: Path | None, db_from_env: bool, cli_key: Path | None, vault_name: str | None,
                cfg: Config, session_db: Path | None) -> tuple[Resolved, VaultRef | None]:
    if cli_db is not None and not db_from_env:
        return Resolved(cli_db, cli_key, "--db"), None
    if vault_name:
        ref = cfg.vaults.get(vault_name)
        if ref is None:
            known = ", ".join(sorted(cfg.vaults)) or "none configured"
            raise ConfigError(f"unknown vault {vault_name!r} (known: {known})")
        return Resolved(ref.path, cli_key or ref.key, f"vault {ref.name!r} from {ref.origin}"), ref
    if cli_db is not None:
        return Resolved(cli_db, cli_key, "KDBX_FILE"), None
    name = cfg.default or (next(iter(cfg.vaults)) if len(cfg.vaults) == 1 else None)
    if name is not None:
        ref = cfg.vaults[name]
        return Resolved(ref.path, cli_key or ref.key, f"default vault {ref.name!r} from {ref.origin}"), ref
    if session_db is not None:
        return Resolved(session_db, cli_key, "the unlocked session"), None
    return Resolved(None, cli_key, "none"), None


def resolve_vault(cli_db: Path | None, db_from_env: bool, cli_key: Path | None, vault_name: str | None,
                  cfg: Config, session_db: Path | None) -> Resolved:
    """Apply the precedences above. `db_from_env`: the --db value came from KDBX_FILE, not the command line.

    The profile is taken from the chosen vault's own config entry, else the config's top-level `profile`;
    `--profile` / PDH_PROFILE is applied by the caller on top of that."""
    picked, ref = _pick_vault(cli_db, db_from_env, cli_key, vault_name, cfg, session_db)
    if ref is not None and ref.profile:
        return replace(picked, profile=ref.profile, profile_source=f"vault {ref.name!r} in {ref.origin}")
    if cfg.profile:
        return replace(picked, profile=cfg.profile, profile_source=f"config {cfg.profile_origin}")
    return picked
