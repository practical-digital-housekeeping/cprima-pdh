"""The borders between the packages: the vault layers know nothing of pdh, and no layer knows a sibling it does not need.

- `cprima_pdh_vault` (the interface): no pdh, no typer, no pydantic, no format library, no other layer.
- `cprima_pdh_kdbxkit` and `cprima_pdh_sopskit`: the vault package and their own format library only; never pdh, typer,
  pydantic, nor each other.
"""
import re
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[3]  # .../packages

CORE = {"cprima_pdh_vault"}
BASE_FORBIDDEN = ("cprima_pdh", "typer", "pydantic")  # `cprima_pdh` itself, not the `cprima_pdh_*` names
FORBIDDEN = {
    "cprima-pdh-vault": BASE_FORBIDDEN + ("cprima_pdh_kdbxkit", "cprima_pdh_sopskit", "pykeepass", "lxml", "cryptography"),
    "cprima-pdh-kdbxkit": BASE_FORBIDDEN + ("cprima_pdh_sopskit", "cryptography"),
    "cprima-pdh-sopskit": BASE_FORBIDDEN + ("cprima_pdh_kdbxkit", "pykeepass", "lxml"),
}


def imports(path: Path) -> set[str]:
    """The top-level package names a file imports (`import a.b`, `from a.b import c`; relative imports stay inside)."""
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*(?:from\s+([A-Za-z_][\w]*)[\w.]*\s+import|import\s+([A-Za-z_][\w]*))", line)
        if match:
            names.add(match.group(1) or match.group(2))
    return names


def test_each_layer_imports_only_what_it_may():
    offenders = []
    for package, forbidden in FORBIDDEN.items():
        for path in sorted((PACKAGES / package / "src").rglob("*.py")):
            offenders += [f"{package}/{path.name} imports {name}" for name in sorted(imports(path)) if name in forbidden]
    assert not offenders, offenders


def test_only_the_kdbx_layer_knows_pykeepass_and_only_the_sops_layer_knows_cryptography():
    pdh = PACKAGES / "cprima-pdh" / "src"
    offenders = [f"{p.name} imports {n}" for p in sorted(pdh.rglob("*.py")) for n in sorted(imports(p))
                 if n in ("pykeepass", "cryptography")]
    assert not offenders, offenders


def test_the_layers_are_where_the_plan_puts_them():
    for package, module in (("cprima-pdh-vault", "vault.py"), ("cprima-pdh-vault", "transaction.py"),
                            ("cprima-pdh-vault", "memory.py"), ("cprima-pdh-kdbxkit", "kdbx_vault.py"),
                            ("cprima-pdh-kdbxkit", "kdbx_format.py"), ("cprima-pdh-sopskit", "sops_vault.py"),
                            ("cprima-pdh-sopskit", "sops_format.py"), ("cprima-pdh-sopskit", "age.py")):
        assert (PACKAGES / package / "src" / package.replace("-", "_") / module).is_file(), (package, module)
