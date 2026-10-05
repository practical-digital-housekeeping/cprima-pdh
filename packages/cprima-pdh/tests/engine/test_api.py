"""The library surface: a vault opened in memory by code. Secrets come back masked, read-only is the default, nothing returns all
secrets, writes go through the verified path, and no secret appears in a repr, an error or any output."""
import re

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pydantic import SecretStr

from cprima_pdh import profiles
from cprima_pdh.api import (
    Account,
    NoSuchAccount,
    OpenError,
    ReadOnly,
    SecretNotSet,
    VaultError,
    open_vault,
)
from cprima_pdh.credentials import KEYFILE_ENV, PASSWORD_ENV, Credentials, from_environment
from cprima_pdh.generate import PasswordSettings
from cprima_pdh_kdbxkit.kdbx_vault import pykeepass_open

BINDING = profiles.load(profiles.DEFAULT).binding.field
SEED = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def db(tmp_path):
    path = synthetic_vault(tmp_path / "v.kdbx", [
        Entry("alice", group="Test accounts", username="alice@example.org", url="https://app.example.org", tags=("qa",),
              password="pw-alice-unique", custom={"role": "admin"}),
        Entry("bob", group="Test accounts", username="bob@example.org"),   # no password yet
        Entry("wifi", group="Lab", custom={BINDING: "wifi-access-point"}),  # wifi_key and Password missing
    ])
    kp = pykeepass_open(path, DEFAULT_PASSWORD, None)
    alice = next(e for e in kp.entries if e.title == "alice")
    alice.otp = f"otpauth://totp/x?secret={SEED}&digits=6"
    alice.set_custom_property("api_token", "tok-alice-unique", protect=True)
    kp.save()
    return path


def reading(db, **kw):
    return open_vault(db, password=DEFAULT_PASSWORD, **kw)


def writing(db):
    return open_vault(db, password=DEFAULT_PASSWORD, write=True)


# --- opening ------------------------------------------------------------------------------------------------------------

def test_the_credentials_come_from_the_arguments_or_the_environment(db, monkeypatch):
    with reading(db) as v:
        assert [a.title for a in v.accounts("Lab")] == ["wifi"]
    monkeypatch.setenv(PASSWORD_ENV, DEFAULT_PASSWORD)
    with open_vault(db) as v:
        assert len(v.accounts()) == 3
    assert from_environment({PASSWORD_ENV: "x", KEYFILE_ENV: "k.key"}) == Credentials(SecretStr("x"), __import__("pathlib").Path("k.key"))
    assert from_environment({PASSWORD_ENV: ""}).password is None  # empty counts as not set


def test_a_wrong_passphrase_is_one_clear_error_that_never_contains_it(db):
    with pytest.raises(OpenError) as raised:
        open_vault(db, password="wrong-passphrase-xyz")
    assert "wrong-passphrase-xyz" not in str(raised.value) and "wrong credentials" in str(raised.value)
    assert "wrong-passphrase-xyz" not in repr(raised.value.__cause__ or "")


def test_a_vault_that_is_not_kdbx_is_refused_by_the_library(tmp_path):
    f = tmp_path / "plain.txt"
    f.write_text("not a vault", encoding="utf-8")
    with pytest.raises(OpenError):
        open_vault(f, password="x")


def test_the_repr_shows_neither_the_passphrase_nor_the_contents(db):
    v = reading(db)
    text = repr(v) + str(v) + repr(v._credentials)
    assert DEFAULT_PASSWORD not in text and "alice" not in text and "read-only" in text
    v.close()
    assert "closed" in repr(v)


def test_a_closed_vault_cannot_be_used_and_has_dropped_its_credentials(db):
    v = reading(db)
    v.close()
    with pytest.raises(VaultError, match="closed"):
        v.accounts()
    assert v._credentials.password is None


# --- reading ------------------------------------------------------------------------------------------------------------

def test_an_account_is_structure_only(db):
    with reading(db) as v:
        a = v.account("Test accounts/alice")
    assert isinstance(a, Account) and (a.username, a.url, a.tags) == ("alice@example.org", "https://app.example.org", ("qa",))
    assert a.fields == {"role": "admin"}  # the protected api_token is left out
    flat = repr(a)
    assert "pw-alice-unique" not in flat and "tok-alice-unique" not in flat and SEED not in flat


def test_accounts_can_be_picked_by_group_and_tag_and_say_what_is_missing(db):
    with reading(db) as v:
        assert [a.title for a in v.accounts("Test accounts")] == ["alice", "bob"]
        assert [a.title for a in v.accounts(tag="qa")] == ["alice"]
        missing = {a.title: a.secrets_missing for a in v.accounts()}
    assert missing["alice"] == () and missing["bob"] == ("Password",) and missing["wifi"] == ("wifi_key", "Password")


def test_a_secret_is_masked_until_the_value_is_asked_for_explicitly(db, capsys):
    with reading(db) as v:
        s = v.secret("Test accounts/alice")
    assert isinstance(s, SecretStr) and s.get_secret_value() == "pw-alice-unique"
    assert "pw-alice-unique" not in f"{s} {s!r}" and str(s) == "**********"
    assert capsys.readouterr().out == ""  # nothing was printed


def test_a_custom_secret_and_the_otp_seed_are_read_by_name(db):
    with reading(db) as v:
        assert v.secret("Test accounts/alice", "api_token").get_secret_value() == "tok-alice-unique"
        assert SEED in v.secret("Test accounts/alice", "otp").get_secret_value()


def test_only_a_secret_field_is_handed_out_as_a_secret(db):
    with reading(db) as v:
        for field in ("URL", "UserName", "Title", "role"):
            with pytest.raises(ValueError, match="is not a secret field"):
                v.secret("Test accounts/alice", field)


def test_a_secret_that_has_no_value_is_an_error_not_an_empty_string(db):
    with reading(db) as v, pytest.raises(SecretNotSet, match="fill it first"):
        v.secret("Test accounts/bob")


def test_there_is_no_call_that_returns_all_secrets(db):
    public = {n for n in dir(reading(db)) if not n.startswith("_")}
    assert not {n for n in public if "dump" in n or "all_secret" in n or n in ("secrets", "get_secrets", "export")}
    assert {"secret", "otp_code"} <= public  # reading is one account and one field at a time


def test_an_unknown_account_is_a_lookup_error(db):
    with reading(db) as v, pytest.raises(NoSuchAccount):
        v.account("Nowhere/nobody")


def test_the_current_one_time_code_is_given_not_the_seed(db):
    with reading(db) as v:
        code = v.otp_code("Test accounts/alice")
        assert code.code.isdigit() and len(code.code) == 6 and SEED not in repr(code)
        with pytest.raises(SecretNotSet, match="no one-time password"):
            v.otp_code("Test accounts/bob")


# --- writing ------------------------------------------------------------------------------------------------------------

def test_a_vault_opened_read_only_refuses_every_change(db):
    before = db.read_bytes()
    with reading(db) as v:
        with pytest.raises(ReadOnly):
            v.set_secret("Test accounts/bob", "Password", "x")
        with pytest.raises(ReadOnly):
            v.fill("Test accounts")
        with pytest.raises(ReadOnly):
            v.add_accounts([{"Title": "x"}])
    assert db.read_bytes() == before


def test_fill_generates_what_is_missing_stores_it_and_returns_no_secret(db, capsys):
    with writing(db) as v:
        result = v.fill("Test accounts", PasswordSettings(length=16, groups=("lower", "digits")))
        assert (result.entries, result.filled, result.still_missing) == (1, 1, ())
        bob = v.secret("Test accounts/bob").get_secret_value()
    assert len(bob) == 16 and bob.isalnum() and bob == bob.lower()
    assert bob not in repr(result) and capsys.readouterr().out == ""


def test_fill_reports_what_it_cannot_generate_and_leaves_what_is_set_alone(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx", [Entry("card", group="Cards", custom={BINDING: "credit-card"}),
                                                Entry("router", group="Cards", custom={BINDING: "openwrt-device"}),
                                                Entry("done", group="Cards", password="keep-me")])
    with writing(db) as v:
        result = v.fill("Cards")
        # a card's number, PIN and CVV and a router's ssh key come from outside: only typed, so only reported
        assert {f for _, f in result.still_missing} == {"card_number", "PIN", "CVV", "ssh_key"}
        assert result.filled == 1  # the router's password, made up
        assert v.secret("Cards/done").get_secret_value() == "keep-me"
        assert v.secret("Cards/router").get_secret_value()
        with pytest.raises(SecretNotSet):
            v.secret("Cards/card", "PIN")  # never generated


def test_set_secret_stores_it_protected_keeps_the_old_value_in_the_history_and_masks_the_new_one(db):
    with writing(db) as v:
        v.set_secret("Test accounts/bob", "recovery_code", SecretStr("RC-1234-5678"))
        v.set_secret("Test accounts/bob", "Password", "bob-typed-secret")
        assert v.secret("Test accounts/bob", "recovery_code").get_secret_value() == "RC-1234-5678"
    bob = next(e for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries if e.title == "bob")
    assert bob.is_custom_property_protected("recovery_code") and bob.password == "bob-typed-secret" and len(bob.history) == 2


def test_set_secrets_is_one_write_with_one_snapshot_per_account(db):
    with writing(db) as v:
        v.set_secrets({"Test accounts/bob": {"Password": "bob-secret-1", "recovery_code": "RC-1"},
                       "Test accounts/alice": {"recovery_code": "RC-2"}})
        assert v.secret("Test accounts/bob").get_secret_value() == "bob-secret-1"
        assert v.secret("Test accounts/alice", "recovery_code").get_secret_value() == "RC-2"
    kp = pykeepass_open(db, DEFAULT_PASSWORD, None)
    assert {e.title: len(e.history) for e in kp.entries if e.title in ("alice", "bob")} == {"alice": 1, "bob": 1}


def test_set_secrets_is_all_or_nothing(db):
    before = db.read_bytes()
    with writing(db) as v, pytest.raises(VaultError, match="is not a secret field"):
        v.set_secrets({"Test accounts/bob": {"Password": "fine-secret"}, "Test accounts/alice": {"URL": "https://x.example.org"}})
    assert db.read_bytes() == before


def test_set_secret_refuses_a_field_that_is_not_a_secret(db):
    with writing(db) as v, pytest.raises(VaultError, match="is not a secret field"):
        v.set_secret("Test accounts/bob", "URL", "https://x.example.org")


def test_a_write_is_refused_while_another_program_has_the_vault_open(db):
    db.with_name(db.name + ".lock").write_text("", encoding="utf-8")  # what a client leaves while it has the vault open
    with writing(db) as v, pytest.raises(VaultError, match="open elsewhere"):
        v.set_secret("Test accounts/bob", "Password", "x")


def test_what_is_written_is_checked_and_the_other_entries_are_untouched(db):
    with writing(db) as v:
        before = {a.path: (a.username, a.url, a.fields) for a in v.accounts() if a.title != "bob"}
        v.set_secret("Test accounts/bob", "Password", "x-secret-value")
        after = {a.path: (a.username, a.url, a.fields) for a in v.accounts() if a.title != "bob"}
    assert before == after and not list(db.parent.glob("*.pdh-new*"))


# --- the whole use case: mass registration for test automation ------------------------------------------------------------

def test_mass_registration_prepare_generate_register_and_record_what_the_site_showed(tmp_path):
    db = synthetic_vault(tmp_path / "v.kdbx")
    users = [{"Group": "Run 7", "Title": f"user{n:03d}", "UserName": f"user{n:03d}@test.example.org", "Tags": "qa;run7"}
             for n in range(40)]
    with writing(db) as v:
        report = v.add_accounts(users, group="Test accounts")
        assert (report.entries, report.secrets_to_fill) == (40, 40)
        assert v.fill("Test accounts").filled == 40
        passwords, seeds = [], {}
        for account in v.accounts(tag="run7"):
            passwords.append(v.secret(account).get_secret_value())  # the automation types this into the registration form
            seeds[account.path] = {"otp": f"otpauth://totp/x?secret={SEED}&digits=6"}  # the seed the site showed on registration
        v.set_secrets(seeds)  # one write for all forty, not forty writes
        assert len(set(passwords)) == 40 and all(len(p) == 20 and p.isalnum() for p in passwords)
        assert v.otp_code(v.accounts(tag="run7")[0]).code.isdigit()
        assert not any(a.secrets_missing for a in v.accounts())


def test_add_accounts_refuses_a_secret_column_like_a_file_does(db):
    with writing(db) as v, pytest.raises(VaultError, match="is for a secret"):
        v.add_accounts([{"Title": "x", "Password": "plain-text-secret"}])


def test_nothing_the_library_does_is_printed(db, capsys):
    with writing(db) as v:
        v.fill("Test accounts")
        v.secret("Test accounts/alice")
        v.set_secret("Test accounts/bob", "otp", f"otpauth://totp/x?secret={SEED}")
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert not re.search(r"pw-alice-unique|tok-alice-unique", captured.out + captured.err)
