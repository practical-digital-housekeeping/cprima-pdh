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
| `pdh edit` | `set`, `fill` (the secret fields an entry or a group still lacks), `link`, `rename-field` (one entry or `--all`), `vocabulary`, `new-entry`, `new-group`, `move`, `delete` (to the recycle bin), `restore`, `purge` (only from the bin), `clone`, `tags`, `expiry`, `icon`, `color`, `override-url`, `autotype`, `history-restore`, `history-prune`, `attach`, `detach`, `rename-group`, `move-group`, `delete-group`, `group-notes`, `group-icon`: dry run unless `--apply`; every edit keeps the previous state in the entry's history |
| `pdh db` | `create`, `password`, `keyfile`, `settings`, `kdf`, `empty-bin`: the database itself (dry run unless `--apply`; new passwords from an environment variable or a hidden prompt) |
| `pdh io` | `import-csv`, `import-xlsx`, `import-kdbx`, `merge` (by UUID and modification time, nothing deleted), `export-csv`, `export-kdbx`, `export-attachment`: the exports are the only writes outside the vault, only to `--out`, never over an existing file |
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
backend = "kdbx"                      # optional: the kind of vault for every vault
[vaults.<name>]
path = "relative/or/absolute.kdbx"
backend = "sops"                      # optional: this vault is of this kind
```

## Which backend

Usually nothing needs saying: pdh looks at the file (the KDBX signature, a `sops` block), and an extension does not
matter. To say it anyway, first match wins: `--backend NAME`, else `PDH_BACKEND`, else the vault's own `backend` in the
config, else the config's top-level `backend`, else the file's content. A choice is always checked against the file: asking
for `sops` on a KDBX file is refused ("is a kdbx file, not sops (chosen by ...)"). A file no backend recognises is an error
that says so, except an empty one, which is treated as KDBX. `pdh backends` lists what is installed, how each kind of file
is recognised and what each can do, and `pdh doctor` says which backend was chosen and by what.

## Data boundary

pdh works with two kinds of user data and treats them differently.

- **Structure**: group, title, user name, URL, tags, expiry and every field the taxonomy does not mark protected. It may be in
  plaintext files such as a spreadsheet (CSV).
- **Secrets**: the standard `Password` and `otp`, every field the taxonomy marks `protected`, every value the vault file itself
  marks protected, and the secret attributes of the KDBX ecosystem (`otp`, `TOTP Seed`, `TOTP Settings`, `TimeOtp-*`,
  `HmacOtp-*`, and a passkey's private key). A value counts as a secret if any of these says so.

**pdh never reads a secret from a plaintext file, and never writes one to a plaintext file.** An input file with a column for a
secret is refused, with the reason and with no way around it. A secret reaches pdh only through a channel that leaves nothing
at rest: a hidden prompt, pdh's own generator, or an encrypted source such as another vault. A secret is never an argument on
the command line.

What the line does not cover: free text. pdh cannot know that someone typed a password into a notes field. Key material that
only decrypts something (a key file, an age identity) is read to open a vault or a sops file and never written by pdh.

The master passphrase of a vault is one secret that opens a store, and it has its own channels: `KDBX_PASSWORD` in the
environment (as CI systems inject it), or `--password-stdin` (read from standard input, which keeps it out of the
environment), or a hidden prompt. A history entry's old values are never printed, searched or exported.

`pdh session unlock` caches the master passphrase for a while (30 minutes by default) so later commands do not ask. The cache is
a file in your profile folder, encrypted with your Windows account's key (DPAPI): it is not plain text, but any process running
as you can read it, so treat it like a key file. An expired cache is deleted by the next pdh command, and `pdh session lock`
deletes it at once. It works on Windows only; elsewhere use `KDBX_PASSWORD` or `--password-stdin`.

## Importing a spreadsheet

`pdh io import-csv FILE` reads a CSV file and `pdh io import-xlsx FILE` an `.xlsx` workbook (its first visible sheet, header in
row 1); each refuses the other's format and names the command to use. Both carry structure only: columns `Group`, `Title` (required), `UserName`, `URL`, `Notes`, `Tags` (`a;b`), `Expires`, and any other column as a
custom field. A column for a secret is refused (see the data boundary), so a password never travels in the file. The new entries
come without secrets, and the report says how many secret fields, by the taxonomy, are still to fill. `pdh edit fill PATH`
(an entry, or a group for everything below it) lists them, and with `--apply` asks for each with a hidden prompt (Enter skips).
With `--generate` the fields the taxonomy allows to be generated, such as a password for an account you are about to register,
are generated and stored without being shown: read them in your KeePass client and paste them into the registration form.
`pdh edit set PATH FIELD -` sets one field. A workbook is read as data only: formulas are not evaluated, and workbooks with
macros, links to other workbooks, binary (`.xls`, `.xlsb`) or OpenDocument form are refused. Format a column as text in your
spreadsheet to keep leading zeros or long numbers. `pdh io export-csv` writes the review file: no secret column, and cells a
spreadsheet would run as a formula are written as text.

## Using pdh from Python

For scripts and test automation, `cprima_pdh.api` opens a vault in memory: no file, no argument, no command line. It is a hobby
project at version 0.x, so this surface can change.

```python
from cprima_pdh.api import open_vault

with open_vault("accounts.kdbx", write=True) as v:      # passphrase from KDBX_PASSWORD; read-only without write=True
    v.add_accounts([{"Title": "user001", "UserName": "user001@test.example.org", "Tags": "qa"}], group="Test accounts")
    v.fill("Test accounts")                              # generate and store the missing passwords; returns no secret
    for account in v.accounts(tag="qa"):
        password = v.secret(account).get_secret_value()  # a SecretStr until you ask for the text
        register(account.username, password)             # your automation
        v.set_secrets({account.path: {"otp": seed_shown_by_the_site}})   # one verified write for many accounts
    code = v.otp_code("Test accounts/user001").code      # the current one-time code, not the seed
```

Secrets come back as `SecretStr`; the module docstring of `cprima_pdh/api.py` says what the library guards and what it cannot.

## Safety

Read-only by default; every write is a dry run unless `--apply`, and is verified by reopening the saved file. pdh
never copies or backs up the vault (backups are your job) and never prints a secret value.

Licence: Apache-2.0.
