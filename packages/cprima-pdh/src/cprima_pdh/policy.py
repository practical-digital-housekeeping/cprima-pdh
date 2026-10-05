"""pdh's choices for the backends it uses, made once, here.

The backends (`cprima_pdh_vault`, `cprima_pdh_kdbxkit`, `cprima_pdh_sopskit`) know nothing of pdh or its method: every rule that is a
choice is a setting with a default that the program using them can replace. This module is where pdh states its own: the rest of
pdh imports these instances and never builds a vault or a write by itself. Another program makes its own module the same way.
"""
from __future__ import annotations

from cprima_pdh_kdbxkit.kdbx_vault import KdbxPolicy, KdbxVault
from cprima_pdh_vault.transaction import WritePolicy
from cprima_pdh_vault.vault import register_adapter

# pdh keeps the KDBX backend's defaults: it names itself in `Meta/Generator` on every save and writes the verified formats only.
KDBX_POLICY = KdbxPolicy()

# pdh's temporary file is recognisable (`vault.pdh-new.kdbx`); its lock-file rule is the backend's default.
WRITE_POLICY = WritePolicy(temp_suffix=".pdh-new")

# The raw pykeepass databases pdh's opening code hands around are wrapped with pdh's policy, ahead of the backend's own default.
register_adapter(KdbxVault.adapter(KDBX_POLICY), first=True)
