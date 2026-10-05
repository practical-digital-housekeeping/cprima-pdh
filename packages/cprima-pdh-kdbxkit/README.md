# cprima-pdh-kdbxkit

KeePass (KDBX 3.1, 4.0, 4.1) vaults for [cprima-pdh](../cprima-pdh), as a layer on [pykeepass](https://github.com/libkeepass/pykeepass).

- `cprima_pdh_kdbxkit.kdbx_vault`: `KdbxVault`, a `cprima_pdh_vault` Vault. Reads and writes; the workarounds for what pykeepass
  does not do (the KDBX 3 header hash, protection of custom fields, trash and restore, history, attachments) stay in this file.
- `cprima_pdh_kdbxkit.kdbx_format`: what the format says, with no pykeepass import.

Depends on `cprima-pdh-vault`, `pykeepass` (GPL-3.0) and `lxml`. Knows nothing of any taxonomy.
Hobby project, 0.x, no stability promised. Apache-2.0 for this code; pykeepass keeps its own licence.
