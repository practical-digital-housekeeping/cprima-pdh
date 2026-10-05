"""The vault interface of cprima-pdh.

`vault` holds the interface (`Vault`, `EntryData`, `GroupData`, `Unsupported`, `WriteError`), `transaction` the one write path
(plan, write once to a temporary file, reopen, verify, replace), `memory` a backend made of plain Python objects. A backend for
a file format lives in its own package (`cprima_pdh_kdbxkit`, `cprima_pdh_sopskit`) and depends on this one, never the reverse.
"""
