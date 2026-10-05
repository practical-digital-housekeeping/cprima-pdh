# cprima-pdh-vault

The vault interface of [cprima-pdh](../cprima-pdh): what the engine may ask of any store of entries.

- `cprima_pdh_vault.vault`: `Vault`, `VaultBase`, `EntryData`, `GroupData`, `Unsupported`, `WriteError`.
- `cprima_pdh_vault.transaction`: the one write path. A command describes a `Plan`; `execute` writes once to a temporary file,
  reopens it, verifies that nothing else changed, and only then replaces the vault. Without `apply` nothing is written.
- `cprima_pdh_vault.memory`: a vault of plain Python objects. It changes entries and groups like the other backends and is
  held to the same results by the shared contract tests.

A file format is its own package and depends on this one: `cprima-pdh-kdbxkit` (KeePass), `cprima-pdh-sopskit` (sops). The model
is KeePass-shaped (standard fields, protected custom fields, a recycle bin), so a store that is nothing like a KeePass vault would
need a mapping. The write path's choices (the name of the temporary file, which lock files stop a write) are a `WritePolicy` the
caller passes, with defaults; `register_adapter(..., first=True)` lets a program wrap a store's own objects with its settings.
No dependencies. Hobby project, 0.x, no stability promised. Apache-2.0.
