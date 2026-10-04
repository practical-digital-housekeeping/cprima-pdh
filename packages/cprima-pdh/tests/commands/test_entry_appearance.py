"""`edit icon` / `color` / `override-url` / `autotype`: how an entry looks and behaves in a client."""
import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault

from cprima_pdh.entries import set_autotype, set_color, set_icon, set_override_url
from cprima_pdh.source import pykeepass_open
from cprima_pdh.write import WriteError
from pdh_testkit.cli import invoke

pytestmark = pytest.mark.usefixtures("opens_with_the_test_password")


def opener(db):
    return lambda: pykeepass_open(db, DEFAULT_PASSWORD, None)


def entry(db, title="a"):
    return next(e for e in pykeepass_open(db, DEFAULT_PASSWORD, None).entries if e.title == title)


@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [Entry("a", group="G", username="u", password="pw", custom={"k": "v"}),
                                                  Entry("b", group="G")])


def text(db, tag):
    return entry(db)._element.findtext(tag)


# --- icon ---------------------------------------------------------------------------------------------------

def test_icon_is_set_with_history_and_a_dry_run_changes_nothing(vault):
    before = vault.read_bytes()
    assert set_icon(opener(vault), vault, "G/a", 12, apply=False).applied is False and vault.read_bytes() == before
    assert set_icon(opener(vault), vault, "G/a", 12, apply=True).applied
    a = entry(vault)
    assert str(a.icon) == "12" and len(a.history) == 1 and (a.username, a.password) == ("u", "pw")


@pytest.mark.parametrize("bad", [-1, 69, 1000])
def test_an_icon_outside_the_standard_set_is_refused(vault, bad):
    with pytest.raises(WriteError, match="icon"):
        set_icon(opener(vault), vault, "G/a", bad, apply=False)


def test_the_same_icon_is_a_noop(vault):
    set_icon(opener(vault), vault, "G/a", 12, apply=True)
    before = vault.read_bytes()
    assert set_icon(opener(vault), vault, "G/a", 12, apply=True).applied is False and vault.read_bytes() == before


# --- colours ------------------------------------------------------------------------------------------------

def test_colours_are_set_and_cleared(vault):
    set_color(opener(vault), vault, "G/a", fg="#112233", bg="#AABBCC", clear=False, apply=True)
    assert (text(vault, "ForegroundColor"), text(vault, "BackgroundColor")) == ("#112233", "#AABBCC")
    set_color(opener(vault), vault, "G/a", fg=None, bg="#000000", clear=False, apply=True)  # only the background
    assert (text(vault, "ForegroundColor"), text(vault, "BackgroundColor")) == ("#112233", "#000000")
    set_color(opener(vault), vault, "G/a", fg=None, bg=None, clear=True, apply=True)
    assert not text(vault, "ForegroundColor") and not text(vault, "BackgroundColor")


@pytest.mark.parametrize("fg,bg,clear", [("red", None, False), ("#12345", None, False), (None, None, False),
                                         ("#112233", None, True)])
def test_colours_need_a_hex_value_or_clear(vault, fg, bg, clear):
    with pytest.raises(WriteError):
        set_color(opener(vault), vault, "G/a", fg=fg, bg=bg, clear=clear, apply=False)


# --- URL override ---------------------------------------------------------------------------------------------

def test_override_url_is_set_and_an_empty_value_removes_it(vault):
    set_override_url(opener(vault), vault, "G/a", "cmd://{URL}", apply=True)
    assert text(vault, "OverrideURL") == "cmd://{URL}" and entry(vault).get_custom_property("k") == "v"
    set_override_url(opener(vault), vault, "G/a", "", apply=True)
    assert not text(vault, "OverrideURL")


# --- auto-type ----------------------------------------------------------------------------------------------

def test_autotype_is_switched_and_its_sequence_set(vault):
    set_autotype(opener(vault), vault, "G/a", enabled=False, sequence="{USERNAME}{TAB}{PASSWORD}{ENTER}", apply=True)
    a = entry(vault)
    assert a.autotype_enabled is False and a.autotype_sequence == "{USERNAME}{TAB}{PASSWORD}{ENTER}"
    set_autotype(opener(vault), vault, "G/a", enabled=True, sequence=None, apply=True)
    assert entry(vault).autotype_enabled is True and entry(vault).autotype_sequence == "{USERNAME}{TAB}{PASSWORD}{ENTER}"


def test_autotype_needs_something_to_change(vault):
    with pytest.raises(WriteError):
        set_autotype(opener(vault), vault, "G/a", enabled=None, sequence=None, apply=False)


# --- the command line ---------------------------------------------------------------------------------------

def test_the_cli_commands(vault):
    assert invoke(vault, "edit", "icon", "G/a", "7", "--apply").exit_code == 0 and str(entry(vault).icon) == "7"
    assert invoke(vault, "edit", "color", "G/a", "--fg", "#010203", "--apply").exit_code == 0
    assert invoke(vault, "edit", "override-url", "G/a", "https://x.example.org", "--apply").exit_code == 0
    assert invoke(vault, "edit", "autotype", "G/a", "--disabled", "--sequence", "{PASSWORD}", "--apply").exit_code == 0
    a = entry(vault)
    assert a.autotype_enabled is False and a._element.findtext("OverrideURL") == "https://x.example.org"
    assert invoke(vault, "edit", "icon", "G/a", "999").exit_code == 2
