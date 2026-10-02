# cprima-pdh

**Practical Digital Housekeeping.** Keep your digital life in order, starting with your password database.
Keep it tidy. Keep it trustworthy.

`pdh` is the companion tool of the methodology: it checks a KeePass vault (`.kdbx`) against a written taxonomy of
record types and field names, and changes the vault only on request, as a dry run first. Website:
https://pdh.cprima.net

```powershell
uvx --from "cprima-pdh[kdbx]" pdh doctor --db vault.kdbx
```

Always use `--from`: plain `uvx pdh` runs an unrelated tool of the same command name. The `[kdbx]` extra installs
pykeepass; the method commands (`pdh method ...`) work without it.

## Commands

| Group | Commands |
|---|---|
| `pdh doctor` | overview in three sections: setup, file (format and key derivation from the header, lock files, sync conflicts, size drivers) and method (owners, areas, record types, vocabulary, conformance, hygiene, relations) |
| `pdh session` | `unlock`, `lock`, `status`: cache the master password for a while (Windows DPAPI) |
| `pdh inspect` | `inventory`, `tree`, `entries`, `tags`, `totp`, `find`, `show`, `read`, `links`, `unclassified`, `fields` |
| `pdh check` | `conform` (the default), `validate`: findings with levels ERROR / WARN / INFO and, per issue, an action |
| `pdh edit` | `set`, `link`, `rename-field`, `vocabulary`, `new-entry`, `new-group`, `move`: dry run unless `--apply` |
| `pdh method` | `show`, `schemas`: the taxonomy, no vault needed |
| `pdh backends` | installed backends |

Use `-f json` for machine-readable output.

## Which vault

`--db PATH`, else `--vault NAME` (or `PDH_VAULT`), else `KDBX_FILE`, else the `default` vault of the config, else the
vault of the unlocked session. Config files, later ones overriding earlier ones: `~/.config/cprima-pdh/config.toml`,
`./pdh.toml`, `$PDH_CONFIG`:

```toml
default = "<name>"
[vaults.<name>]
path = "relative/or/absolute.kdbx"
```

## Safety

Read-only by default; every write is a dry run unless `--apply`, and is verified by reopening the saved file. pdh
never copies or backs up the vault (backups are your job) and never prints a secret value.

Licence: Apache-2.0.
