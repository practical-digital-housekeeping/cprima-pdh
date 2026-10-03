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
| `pdh inspect` | `inventory`, `tree`, `entries` (`--expired`, `--expiring DAYS`), `tags`, `totp`, `find` (`--in-fields`), `show`, `read`, `links`, `unclassified`, `fields`, `history`, `attachments`, `otp` (the current code, never the secret) |
| `pdh check` | `conform` (the default), `validate`: findings with levels ERROR / WARN / INFO and, per issue, an action; `known-passwords` and `breaches` (online, only with `--online`) |
| `pdh edit` | `set`, `link`, `rename-field` (one entry or `--all`), `vocabulary`, `new-entry`, `new-group`, `move`, `delete` (to the recycle bin), `restore`, `purge` (only from the bin), `clone`, `tags`, `expiry`, `icon`, `color`, `override-url`, `autotype`, `history-restore`, `history-prune`, `attach`, `detach`, `rename-group`, `move-group`, `delete-group`, `group-notes`, `group-icon`: dry run unless `--apply`; every edit keeps the previous state in the entry's history |
| `pdh db` | `create`, `password`, `keyfile`, `settings`, `kdf`, `empty-bin`: the database itself (dry run unless `--apply`; new passwords from an environment variable or a hidden prompt) |
| `pdh io` | `import-csv`, `import-kdbx`, `merge` (by UUID and modification time, nothing deleted), `export-csv`, `export-kdbx`, `export-attachment`: the exports are the only writes outside the vault, only to `--out`, never over an existing file |
| `pdh generate` | a password or passphrase from the system's secure random source; printed, never stored |
| `pdh method` | `show`, `schemas`: the taxonomy, no vault needed |
| `pdh backends` | installed backends |

Planned, present in `--help` as `(planned)` and exiting with code 3 until built: `pdh serve` (a local, token-protected,
read-only HTTP API for one-time-password codes and secret-free entry data; loopback only).

Every vault function a GUI client offers is a command; what pdh does not do is auto-type, browser integration and
the graphical UI itself. KDBX 3 to 4 conversion is not offered (pykeepass cannot convert).

Online checks never run without `--online`. `check known-passwords` sends only the first 5 characters of each SHA-1
(k-anonymity); `check breaches` downloads the public breach catalogue and compares it with your URLs locally;
`--accounts` (an API key in `HIBP_API_KEY`) is the one option that sends e-mail addresses. Level and advice of each
finding come from the profile (`known-password`, `breach:*`); `--fail-on LEVEL` sets the exit code like `check validate`.

What only a human with the real clients can verify is listed in [docs/testing/manual-e2e.md](https://github.com/practical-digital-housekeeping/cprima-pdh/blob/main/docs/testing/manual-e2e.md).

Use `-f json` for machine-readable output.

## Stores (backends)

| Backend | Reads | Writes | Extra |
|---|---|---|---|
| `kdbx` | KeePass KDBX 3.1, 4.0, 4.1 (AES, ChaCha20, Twofish; Argon2d, Argon2id, AES-KDF) | yes, everything in the table above | `cprima-pdh[kdbx]` |
| `sops` | a [sops](https://github.com/getsops/sops) JSON file encrypted to age recipients | not yet | `cprima-pdh[sops]` |

pdh recognises the kind of file from its content, so `pdh --db secrets.enc.json inspect tree` just works. For a sops file the
age identity comes from `--key FILE`, else `SOPS_AGE_KEY` / `SOPS_AGE_KEY_FILE`, else sops' default key file. One file is one vault:
a mapping of mappings is a group, a mapping of scalars is an entry, a leaf is a field. Values sops encrypted are protected
fields; titles, group names and field names are the file's plaintext keys. The file's MAC is verified first, so an altered or
reordered file is refused. A sops file has no recycle bin, history, attachments or expiry; commands that need those say so
(`this backend does not support history`). Every read command, the profile checks and `doctor` run on both stores through the same
engine. YAML sops files and writing come later.

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
