"""`fix` planning (renames + fixed protection) on in-memory entries. Only the plan, no writing."""
import pytest
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.fix import _plan
from cprima_pdh.schema import parse_schemas

SSET = parse_schemas("""
[field.secret]
match = '(?i)token|api[ _-]?key'
protected = true

[field.serial_number]
aliases = ["serialnumber"]
protected = false

[field.customer_no]
aliases = ["customerno"]
protected = false
""")


def plan(entry, renames=True, protection=True):
    _ops, actions = _plan(StubKP([entry]), SSET, renames, protection)
    return [(a.action, a.key, a.new_key) for a in actions]


# (case id, entry, flags, expected actions as (action, key, new_key))
CASES = [
    ("rename-alias", E(custom={"serialnumber": "1"}), {}, [("rename", "serialnumber", "serial_number")]),
    ("protect-secret", E(custom={"apikey": "k"}), {}, [("protect", "apikey", None)]),
    ("nothing-to-do", E(custom={"serial_number": "1", "apikey": "k"}, protected=("apikey",)), {}, []),
    ("rename-and-unprotect",
     E(custom={"customerno": "K1"}, protected=("customerno",)), {},
     [("rename", "customerno", "customer_no"), ("unprotect", "customer_no", None)]),
    ("conflict-is-skipped-not-merged",
     E(custom={"serialnumber": "1", "serial_number": "2"}), {},
     [("skipped: serial_number already exists", "serialnumber", "serial_number")]),
    ("only-renames", E(custom={"serialnumber": "1", "apikey": "k"}), {"protection": False},
     [("rename", "serialnumber", "serial_number")]),
    ("only-protection", E(custom={"serialnumber": "1", "apikey": "k"}), {"renames": False},
     [("protect", "apikey", None)]),
    ("unrelated-fields-untouched", E(custom={"totally-unrelated": "x"}), {}, []),
    ("otp-fields-untouched", E(custom={"TimeOtp-Secret": "x"}, totp="otpauth://totp/x?secret=A"), {}, []),
]


@pytest.mark.parametrize("entry,flags,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_fix_plan(entry, flags, expected):
    assert plan(entry, **flags) == expected


def test_plan_never_contains_values():
    secret = "VALUE-THAT-MUST-NOT-LEAK"
    _ops, actions = _plan(StubKP([E(custom={"apikey": secret, "serialnumber": secret})]), SSET, True, True)
    assert secret not in " ".join(str(a) + a.model_dump_json() for a in actions)
