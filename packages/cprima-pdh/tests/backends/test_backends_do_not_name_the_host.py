"""The backends know no program and no method: no source line of them names pdh, a profile, a taxonomy or a methodology. What is a
choice is a setting (`WritePolicy`, `KdbxPolicy`) that the program using them supplies; pdh supplies its own in `cprima_pdh.policy`.

Their own package names (`cprima-pdh-vault`, `cprima-pdh-kdbxkit`, `cprima-pdh-sopskit`) are allowed until they are renamed.
"""
import re
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[3]  # .../packages
BACKENDS = ("cprima-pdh-vault", "cprima-pdh-kdbxkit", "cprima-pdh-sopskit")
OWN_NAMES = re.compile(r"cprima[-_]pdh[-_](vault|kdbxkit|sopskit)")
HOST_OR_METHOD = re.compile(r"\b(pdh|profiles?|taxonom\w*|methodolog\w*)\b", re.IGNORECASE)


def test_no_backend_source_line_names_the_host_or_the_method():
    offenders = []
    for package in BACKENDS:
        for path in sorted((PACKAGES / package / "src").rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if HOST_OR_METHOD.search(OWN_NAMES.sub("", line)):
                    offenders.append(f"{package}/{path.name}:{number}: {line.strip()[:80]}")
    assert not offenders, offenders


def test_the_guard_finds_what_it_is_meant_to_find():
    assert HOST_OR_METHOD.search(OWN_NAMES.sub("", "the profile's names")) and HOST_OR_METHOD.search("pdh never")
    assert not HOST_OR_METHOD.search(OWN_NAMES.sub("", 'GENERATOR = "cprima-pdh-kdbxkit"'))
