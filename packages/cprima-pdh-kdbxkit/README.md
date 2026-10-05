# cprima-pdh-kdbxkit

KeePass (KDBX 3.1, 4.0, 4.1) vaults for [cprima-pdh](../cprima-pdh), as a layer on [pykeepass](https://github.com/libkeepass/pykeepass).

- `cprima_pdh_kdbxkit.kdbx_vault`: `KdbxVault`, a `cprima_pdh_vault` Vault. Reads and writes; the workarounds for what pykeepass
  does not do (the KDBX 3 header hash, protection of custom fields, trash and restore, history, attachments) stay in this file.
- `cprima_pdh_kdbxkit.kdbx_format`: what the format says, with no pykeepass import.

The layer has opinions, and each one that is a choice is a setting with a default (`KdbxPolicy`): it names itself in
`Meta/Generator` on every save (`generator`, or `None` to leave the element alone), and it writes only the formats verified
against genuine KeePassXC files (`writable_formats`, or `None` for any). A program that uses the layer makes one instance in its
own module and passes it, so it has full reign:

```python
from cprima_pdh_kdbxkit.kdbx_vault import KdbxPolicy, KdbxVault

POLICY = KdbxPolicy(generator="my-app", writable_formats=None)  # once, in your own module
vault = KdbxVault.open("vault.kdbx", password, policy=POLICY)
```

What is not a setting: a permanent delete always writes a deletion record, because without one a merge cannot tell a deleted entry
from one that never arrived.

Depends on `cprima-pdh-vault`, `pykeepass` (GPL-3.0) and `lxml`. Knows nothing of any taxonomy.
Hobby project, 0.x, no stability promised. Apache-2.0 for this code; pykeepass keeps its own licence.
