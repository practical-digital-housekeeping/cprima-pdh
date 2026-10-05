"""The vault interface: what a program that works on vaults relies on, whatever the file format.

`vault` holds the interface (`Vault`, `EntryData`, `GroupData`, `Unsupported`, `WriteError`), `transaction` the one write path
(plan, write once to a temporary file, reopen, verify, replace), `memory` a backend made of plain Python objects. A backend for
a file format lives in its own package (`cprima_pdh_kdbxkit`, `cprima_pdh_sopskit`) and depends on this one, never the reverse.
The choices of the write path are a `transaction.WritePolicy` the caller passes, with defaults.
"""
