"""`pdh generate` (password or passphrase, printed, never stored) and `pdh inspect otp` (the current code, never the secret)."""
import json

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from typer.testing import CliRunner

from cprima_pdh import otp
from cprima_pdh.cli import app

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


# --- generate: the CLI (the generator itself is tested in tests/unit/test_generator.py) -----------------------------------

def test_the_generate_command_prints_through_the_renderer():
    result = CliRunner().invoke(app, ["generate", "--length", "24", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and len(data["value"]) == 24 and data["kind"] == "password" and data["entropy_bits"] > 100


def test_the_generate_command_makes_a_passphrase_from_a_word_file(tmp_path):
    f = tmp_path / "words.txt"
    f.write_text("\n".join(f"w{i:04d}" for i in range(2048)), encoding="utf-8")
    result = CliRunner().invoke(app, ["generate", "--passphrase", "--words", str(f), "--count", "5", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and data["kind"] == "passphrase" and len(data["value"].split("-")) == 5
    assert data["entropy_bits"] == pytest.approx(5 * 11, abs=0.01)  # 2048 words = 11 bits each


def test_generate_refuses_bad_options(tmp_path):
    assert CliRunner().invoke(app, ["generate", "--length", "3"]).exit_code == 2
    assert CliRunner().invoke(app, ["generate", "--passphrase"]).exit_code == 2  # no word list
    assert CliRunner().invoke(app, ["generate", "--passphrase", "--words", str(tmp_path / "nope")]).exit_code == 2


# --- one-time passwords: the RFC test vectors ---------------------------------------------------------------------

B32_SHA1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"


@pytest.mark.parametrize("at,digits,expected", [(59, 8, "94287082"), (1111111109, 8, "07081804"), (59, 6, "287082")])
def test_totp_sha1_matches_rfc_6238(at, digits, expected):
    params = otp.parse(f"otpauth://totp/x?secret={B32_SHA1}&digits={digits}")
    assert otp.code(params, at).code == expected


def test_totp_sha256_and_sha512_match_rfc_6238():
    import base64

    s256 = base64.b32encode(b"12345678901234567890123456789012").decode()
    s512 = base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode()
    assert otp.code(otp.parse(f"otpauth://totp/x?secret={s256}&digits=8&algorithm=SHA256"), 59).code == "46119246"
    assert otp.code(otp.parse(f"otpauth://totp/x?secret={s512}&digits=8&algorithm=SHA512"), 59).code == "90693936"


def test_hotp_matches_rfc_4226():
    params = otp.parse(f"otpauth://hotp/x?secret={B32_SHA1}&counter=0")
    assert otp.code(params, 0).code == "755224"


def test_the_period_and_remaining_seconds():
    c = otp.code(otp.parse(f"otpauth://totp/x?secret={B32_SHA1}&period=30"), 59)
    assert (c.period, c.valid_for) == (30, 1)


def test_keepassxc_plain_and_steam_formats():
    plain = otp.parse(f"key={B32_SHA1}&size=6&step=30")
    assert otp.code(plain, 59).code == "287082"
    steam = otp.code(otp.parse(f"otpauth://totp/x?secret={B32_SHA1}&encoder=steam"), 59).code
    assert len(steam) == 5 and set(steam) <= set("23456789BCDFGHJKMNPQRTVWXY")


def test_a_secret_with_spaces_and_lower_case_is_accepted():
    assert otp.code(otp.parse("otpauth://totp/x?secret=" + B32_SHA1.lower()[:16] + "%20" + B32_SHA1.lower()[16:]), 59).code \
        == otp.code(otp.parse(f"otpauth://totp/x?secret={B32_SHA1}"), 59).code


@pytest.mark.parametrize("bad", ["", "not an otp", "otpauth://totp/x", "otpauth://totp/x?secret=!!!",
                                 f"otpauth://totp/x?secret={B32_SHA1}&digits=3", f"otpauth://totp/x?secret={B32_SHA1}&algorithm=MD5"])
def test_unusable_values_are_refused(bad):
    with pytest.raises(ValueError):
        otp.parse(bad)


def test_the_keepass_2_plugin_fields_are_understood():
    fields = {"TimeOtp-Secret-Base32": B32_SHA1, "TimeOtp-Length": "8", "TimeOtp-Period": "30",
              "TimeOtp-Algorithm": "HMAC-SHA-1"}
    assert otp.from_plugin_fields(fields) is not None
    assert otp.code(otp.from_plugin_fields(fields), 59).code == "94287082"
    assert otp.from_plugin_fields({"other": "x"}) is None


# --- the inspect command ------------------------------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("with otp", group="G"), Entry("none", group="G"),
                                                Entry("plugin", group="G", custom={
                                                    "TimeOtp-Secret-Base32": B32_SHA1, "TimeOtp-Length": "6"})])
    from pykeepass import PyKeePass
    kp = PyKeePass(str(db), password=DEFAULT_PASSWORD)
    next(e for e in kp.entries if e.title == "with otp").otp = f"otpauth://totp/x?secret={B32_SHA1}&digits=6"
    kp.save()
    return db


def test_the_command_prints_a_code_and_never_the_secret(vault):
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", "otp", "G/with otp", "-f", "json"])
    data = json.loads(result.stdout)
    assert result.exit_code == 0 and len(data["code"]) == 6 and data["code"].isdigit() and 1 <= data["valid_for"] <= 30
    assert B32_SHA1 not in result.stdout


def test_the_command_reads_the_plugin_fields_too(vault):
    result = CliRunner().invoke(app, ["--db", str(vault), "inspect", "otp", "G/plugin", "-f", "json"])
    assert result.exit_code == 0 and len(json.loads(result.stdout)["code"]) == 6


def test_an_entry_without_a_one_time_password_exits_1(vault):
    assert CliRunner().invoke(app, ["--db", str(vault), "inspect", "otp", "G/none"]).exit_code == 1
