"""There is one write path: no module but `txn` saves a vault, apart from the two that create a new file."""
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "cprima_pdh"
MAY_SAVE = {"source.py": "save_vault, the one place that saves (and keeps a KDBX 3 header hash valid)",
            "export.py": "export_kdbx writes a copy to a new, exclusively created file; the vault itself is untouched",
            "kdbx_vault.py": "KdbxVault.create makes a new vault file",
            "txn.py": "execute_vault, the one write path: the vault saves to a temporary file that replaces it once verified"}


def test_only_save_vault_and_the_file_creator_call_save():
    offenders = sorted(p.name for p in SRC.rglob("*.py") if ".save(" in p.read_text(encoding="utf-8") and p.name not in MAY_SAVE)
    assert not offenders, f"{offenders} save a vault themselves: go through txn.execute"


def test_no_module_keeps_its_own_copy_of_the_verification_helpers():
    text = {p.name: p.read_text(encoding="utf-8") for p in SRC.rglob("*.py")}
    for helper in ("def _check_untouched", "def _digests(", "def _commit(", "def _snapshot("):
        assert [n for n, t in text.items() if helper in t and n != "txn.py"] == [], helper
