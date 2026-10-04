"""The data boundary: pdh never reads a secret from a plaintext file. An import file with a column for a secret is refused,
with the reason, with no override, in a dry run as well, and without ever echoing a value from the file.
"""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, synthetic_vault
from pdh_testkit.cli import invoke

from cprima_pdh.source import pykeepass_open

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")

SECRET_VALUE = "hunter2-must-never-be-echoed"


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "target.kdbx")


def csv_with(tmp_path, column: str, value: str = SECRET_VALUE):
    path = tmp_path / "in.csv"
    path.write_text(f"Group,Title,UserName,URL,{column}\nShops,Acme,alex,https://acme.example.org,{value}\n", encoding="utf-8")
    return path


def entries(db):
    return [e.title for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries]


# what counts as a secret column: the standard secrets, the KDBX ecosystem's, and what the profile marks protected
STANDARD = ["Password", "password", "PASSWORD", "OTP", "otp"]
ECOSYSTEM = ["TOTP Seed", "TOTP Settings", "TimeOtp-Secret-Base32", "HmacOtp-Secret", "KPEX_PASSKEY_PRIVATE_KEY_PEM"]
PROFILE = ["api_token", "api_key"]  # the default profile marks these protected (see [field.secret] in the profile)
SECRET_COLUMNS = STANDARD + ECOSYSTEM + PROFILE


@pytest.mark.parametrize("column", SECRET_COLUMNS)
@pytest.mark.parametrize("apply", [[], ["--apply"]], ids=["dry-run", "applied"])
def test_a_secret_column_is_refused(vault, tmp_path, column, apply):
    result = invoke(vault, "io", "import-csv", str(csv_with(tmp_path, column)), "--group", "Imported", *apply)
    shown = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2
    assert f"column {column!r} is for a secret" in shown and "does not read secrets from files" in shown
    assert SECRET_VALUE not in shown, "the refusal must not echo a value from the file"
    assert entries(vault) == [], "a refused file changes nothing"


def test_the_refusal_points_to_the_way_to_add_the_secret(vault, tmp_path):
    result = invoke(vault, "io", "import-csv", str(csv_with(tmp_path, "Password")), "--group", "Imported")
    assert "pdh edit set" in result.stderr and " -" in result.stderr


def test_every_secret_column_is_named_when_there_are_several(vault, tmp_path):
    path = tmp_path / "in.csv"
    path.write_text("Title,Password,OTP\nAcme,x,y\n", encoding="utf-8")
    result = invoke(vault, "io", "import-csv", str(path), "--group", "Imported")
    assert "'Password'" in result.stderr and "'OTP'" in result.stderr


@pytest.mark.parametrize("column", ["customer_no", "account_no", "Phone", "Department"])
def test_a_structure_column_is_accepted_as_a_custom_field(vault, tmp_path, column):
    result = invoke(vault, "io", "import-csv", str(csv_with(tmp_path, column, "4711")), "--group", "Imported", "--apply")
    assert result.exit_code == 0, result.stderr
    kp = pykeepass_open(vault, DEFAULT_PASSWORD, None)
    assert next(e for e in kp.entries if e.title == "Acme").get_custom_property(column) == "4711"


def test_a_secret_column_is_refused_whatever_the_other_columns_hold(vault, tmp_path):
    path = tmp_path / "in.csv"
    path.write_text("Title,UserName,customer_no,password\nAcme,alex,4711,\n", encoding="utf-8")  # even an empty secret column
    assert invoke(vault, "io", "import-csv", str(path), "--group", "Imported").exit_code == 2
