"""No way to delete for good escapes the record: a delete needs a `DeletedObject`, otherwise a merge cannot tell a deleted entry
from one that never arrived. In the KDBX layer every function that calls a pykeepass delete also records it."""
import ast
from pathlib import Path

LAYER = Path(__file__).resolve().parents[3] / "cprima-pdh-kdbxkit" / "src" / "cprima_pdh_kdbxkit" / "kdbx_vault.py"
DELETES = {"delete_entry", "delete_group", "empty_group", "delete"}  # pykeepass calls that remove an entry or a group for good


def calls(node) -> set[str]:
    return {c.func.attr for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}


def test_every_function_that_deletes_for_good_also_records_it():
    tree = ast.parse(LAYER.read_text(encoding="utf-8"))
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    deleting = {f.name: calls(f) for f in functions if calls(f) & DELETES}
    assert {"purge_entry", "purge_group", "empty_bin"} <= set(deleting), "the guard no longer finds the deleting functions"
    unrecorded = [name for name, used in deleting.items() if "record_deleted" not in used]
    assert not unrecorded, f"{unrecorded} delete for good without recording it"
