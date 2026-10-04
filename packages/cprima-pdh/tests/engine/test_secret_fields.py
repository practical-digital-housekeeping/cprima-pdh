"""The secret fields of an entry come from the taxonomy: which they are, in what order, which are empty, which may be generated,
and filling them in one write without a value ever appearing in a report."""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault

from cprima_pdh import boundary, profiles, secret_fields
from cprima_pdh.source import pykeepass_open
from cprima_pdh.vault import EntryData, Field
from cprima_pdh.write import WriteError

SSET = profiles.load(profiles.DEFAULT)
BINDING = SSET.binding.field


def typed(schema: str | None, **fields: str) -> EntryData:
    custom = {name: Field(value, True) for name, value in fields.items()}
    if schema:
        custom[BINDING] = Field(schema, False)
    return EntryData(id="e", group_path="G", title="t", fields=custom)


def names(entry: EntryData) -> list[str]:
    return [f.name for f in secret_fields.secret_fields(entry, SSET)]


def test_an_entry_without_a_record_type_has_the_secret_a_login_has():
    assert secret_fields.secret_fields(typed(None), SSET) == [secret_fields.SecretField("Password", True)]


def test_the_password_is_one_secret_field_among_the_others_in_the_taxonomys_order():
    assert names(typed("website")) == ["Password"]
    assert names(typed("wifi-access-point")) == ["wifi_key", "Password"]  # the order the taxonomy lists them
    assert names(typed("credit-card")) == ["card_number", "PIN", "CVV"]


def test_a_field_is_generatable_only_when_the_taxonomy_opts_it_in():
    by_name = {f.name: f.generatable for f in secret_fields.secret_fields(typed("credit-card"), SSET)}
    assert by_name == {"card_number": False, "PIN": False, "CVV": False}  # issued by the bank: only typed
    assert {f.name: f.generatable for f in secret_fields.secret_fields(typed("website"), SSET)}["Password"] is True
    assert {f.name: f.generatable for f in secret_fields.secret_fields(typed("wifi-access-point"), SSET)} == {
        "wifi_key": True, "Password": True}  # the access point's secret and its admin's password are made up


@pytest.mark.parametrize("schema,field", [("sim-card", "PIN"), ("sim-card", "PUK"), ("onlineshop", "license_key"),
                                          ("hsm", "so_pin"), ("openwrt-device", "ssh_key")])
def test_what_comes_from_outside_is_never_generatable(schema, field):
    by_name = {f.name: f.generatable for f in secret_fields.secret_fields(typed(schema), SSET)}
    assert by_name[field] is False


def test_only_the_terms_the_taxonomy_opts_in_are_generatable_anywhere_in_the_profile():
    opted = {n for n, ft in SSET.fields.items() if ft.generate} | {n for n, s in SSET.standard.items() if s.generate}
    assert opted == {"wifi_key", "Password"}
    found = {f.name for schema in SSET.schemas for f in secret_fields.secret_fields(typed(schema), SSET) if f.generatable}
    assert found <= opted


@pytest.mark.parametrize("schema", sorted(SSET.schemas))
def test_every_secret_field_of_every_record_type_is_a_secret_under_the_boundary(schema):
    found = names(typed(schema))
    assert len(found) == len(set(found))
    for name in found:
        assert name in ("Password", "otp") or boundary.secret_columns([name], SSET), f"{name} is not a secret under the boundary"


def test_missing_lists_what_is_still_empty():
    assert names(typed("wifi-access-point")) == ["wifi_key", "Password"]
    empty = typed("wifi-access-point")
    assert [f.name for f in secret_fields.missing(empty, SSET)] == ["wifi_key", "Password"]
    partly = EntryData(id="e", group_path="G", title="t", password="set-already",
                       fields={BINDING: Field("wifi-access-point", False), "wifi_key": Field("", True)})
    assert [f.name for f in secret_fields.missing(partly, SSET)] == ["wifi_key"]


def test_a_generated_password_is_random_and_follows_the_settings_it_is_given():
    from cprima_pdh.generate import DEFAULT_LENGTH, PasswordSettings

    a, b = secret_fields.generated(), secret_fields.generated()
    assert len(a) == DEFAULT_LENGTH and a != b
    assert len(secret_fields.generated(PasswordSettings(length=12, groups=("digits",)))) == 12


# --- filling ----------------------------------------------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("ap", group="Home", custom={BINDING: "wifi-access-point", "ssid": "casa"}),
        Entry("site", group="Home"),
    ])


def opener(db):
    return lambda: pykeepass_open(db, DEFAULT_PASSWORD, None)


def entry(db, title):
    return next(e for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries if e.title == title)


def fill(db, values, apply=True, path="Home/ap"):
    return secret_fields.fill(opener(db), db, path, values, apply, SSET)


def test_the_secret_fields_are_written_protected_in_one_write_with_one_history_snapshot(vault):
    change = fill(vault, {"wifi_key": "key-123-secret", "Password": "pw-456-secret"})
    e = entry(vault, "ap")
    assert (e.password, e.get_custom_property("wifi_key")) == ("pw-456-secret", "key-123-secret")
    assert e.is_custom_property_protected("wifi_key") and len(e.history) == 1
    assert change.applied and change.dest == "wifi_key, Password"


def test_the_report_names_the_fields_and_never_a_value(vault):
    change = fill(vault, {"wifi_key": "key-123-secret"})
    assert "key-123-secret" not in change.model_dump_json()


def test_a_dry_run_writes_nothing(vault):
    before = vault.read_bytes()
    assert fill(vault, {"wifi_key": "k"}, apply=False).applied is False
    assert vault.read_bytes() == before


@pytest.mark.parametrize("values", [{"URL": "https://x.example.org"}, {"ssid": "other"}, {"card_number": "4111"}],
                         ids=["standard but not secret", "custom but not secret", "secret of another record type"])
def test_only_the_entrys_own_secret_fields_can_be_filled(vault, values):
    with pytest.raises(WriteError, match="is not a secret field of"):
        fill(vault, values)


def test_an_empty_value_is_not_a_secret(vault):
    with pytest.raises(WriteError, match="an empty value is not a secret"):
        fill(vault, {"wifi_key": ""})


def test_an_untyped_entry_can_be_given_its_password(vault):
    fill(vault, {"Password": "login-pw"}, path="Home/site")
    assert entry(vault, "site").password == "login-pw"
