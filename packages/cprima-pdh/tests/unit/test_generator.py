"""The generator: the knobs of KeePassXC and KeePassDX (groups of characters, include and exclude, look-alikes, a character
from every group, passphrase words, separator and case), drawn from the operating system's secure random source."""
import json
import string

import pytest
from typer.testing import CliRunner

from cprima_pdh import generate as g
from cprima_pdh.cli import app
from cprima_pdh.generate import PassphraseSettings, PasswordSettings

N = 200  # passwords drawn per property: a property of every one of them, not of a lucky one


def many(settings: PasswordSettings) -> list[str]:
    return [g.generate_password(settings) for _ in range(N)]


# --- the groups ---------------------------------------------------------------------------------------------------------

def test_the_groups_hold_exactly_the_characters_both_clients_use():
    assert g.GROUPS["lower"] == string.ascii_lowercase and g.GROUPS["upper"] == string.ascii_uppercase
    assert g.GROUPS["digits"] == string.digits
    assert set(g.GROUPS["braces"]) == set("()[]{}") and set(g.GROUPS["punctuation"]) == set(",.:;")
    assert set(g.GROUPS["quotes"]) == set("\"'") and set(g.GROUPS["dashes"]) == set("-/\\_|")
    assert set(g.GROUPS["math"]) == set("!*+<=>?") and set(g.GROUPS["logograms"]) == set("#$%&@^`~")
    assert g.GROUPS["space"] == " "


def test_extended_is_printable_latin_1_without_the_soft_hyphen_and_the_no_break_space():
    extended = g.GROUPS["extended"]
    assert extended[0] == "\u00a1" and extended[-1] == "\u00ff" and "\u00ad" not in extended and "\u00a0" not in extended


def test_special_is_all_the_special_groups_together_and_has_every_character_of_both_clients_specials():
    special = "".join(g.GROUPS[n] for n in g.SPECIAL)
    assert set("&/,^@.#:%\\='$!?*`;+\"|~[]{}()<>-_") <= set(special)  # KeePassDX's special, bracket, minus and underline sets


def test_the_default_is_letters_and_digits_of_a_length_most_sites_accept():
    s = PasswordSettings()
    assert (s.length, s.groups, s.exclude_similar, s.every_group) == (20, ("lower", "upper", "digits"), True, True)


# --- passwords ----------------------------------------------------------------------------------------------------------

def test_every_password_has_the_length_and_draws_only_from_the_groups():
    for p in many(PasswordSettings(length=24)):
        assert len(p) == 24 and all(c in string.ascii_letters + string.digits for c in p)


def test_with_every_group_every_password_has_a_character_from_each_group():
    settings = PasswordSettings(length=12).with_groups(special=True)
    for p in many(settings):
        for name in settings.groups:
            assert any(c in g.GROUPS[name] for c in p), f"no {name} in {p!r}"


def test_without_every_group_a_password_may_lack_one(monkeypatch):
    # a password of the minimum length from one big alphabet: across many draws one group is missing at least once
    settings = PasswordSettings(length=8, every_group=False)
    assert any(not any(c.isdigit() for c in p) for p in many(settings))


def test_exclude_similar_leaves_out_what_looks_alike_and_exclude_leaves_out_what_is_named():
    settings = PasswordSettings(length=40, exclude="aZ9")
    for p in many(settings):
        assert not set(p) & set(g.SIMILAR) and not set(p) & set("aZ9")


def test_look_alikes_come_back_when_they_are_allowed():
    seen = set("".join(many(PasswordSettings(length=40, exclude_similar=False))))
    assert set("0Ol1I") & seen


def test_include_adds_characters_as_a_group_of_its_own_and_every_group_covers_it():
    settings = PasswordSettings(length=12, include="#")
    assert all("#" in p for p in many(settings))


def test_include_is_not_drawn_when_it_is_also_excluded():
    with pytest.raises(ValueError, match="every character to include is also excluded"):
        g.generate_password(PasswordSettings(include="#", exclude="#"))


@pytest.mark.parametrize("settings,message", [
    (PasswordSettings(length=7), "at least 8"),
    (PasswordSettings(groups=()), "no character group is selected"),
    (PasswordSettings(groups=("nonsense",)), "unknown character group"),
    (PasswordSettings(exclude=string.digits), "group 'digits' has no character left"),
    (PasswordSettings(length=8).with_groups(special=True, extended=True, space=True), "at least that many characters"),
])
def test_settings_that_cannot_make_a_password_are_refused_with_the_reason(settings, message):
    with pytest.raises(ValueError, match=message):
        g.generate_password(settings)


def test_two_passwords_differ():
    assert len(set(many(PasswordSettings(length=24)))) == N


def test_the_entropy_is_the_length_times_the_bits_of_the_alphabet_left():
    import math

    s = PasswordSettings(length=20)
    alphabet = set(string.ascii_letters + string.digits) - set(g.SIMILAR)
    assert g.password_entropy(s) == pytest.approx(20 * math.log2(len(alphabet)))
    assert g.password_entropy(PasswordSettings(length=20, exclude_similar=False)) > g.password_entropy(s)


def test_the_characters_come_from_the_systems_secure_source(monkeypatch):
    calls = []
    real = g.secrets.choice
    monkeypatch.setattr(g.secrets, "choice", lambda seq: (calls.append(1), real(seq))[1])
    g.generate_password(PasswordSettings(length=16))
    assert len(calls) == 16


# --- passphrases --------------------------------------------------------------------------------------------------------

WORDS = [f"word{i:04d}" for i in range(2048)]


def test_a_passphrase_takes_words_from_the_list_only_with_the_separator():
    phrase = g.generate_passphrase(WORDS, PassphraseSettings(words=6, separator="."))
    assert len(phrase.split(".")) == 6 and all(w in WORDS for w in phrase.split("."))


@pytest.mark.parametrize("case,check", [("lower", str.islower), ("upper", str.isupper), ("title", str.istitle)])
def test_the_word_case_is_applied(case, check):
    assert all(check(w) for w in g.generate_passphrase(WORDS, PassphraseSettings(case=case)).split("-"))


def test_a_passphrase_needs_a_long_enough_list_enough_words_and_a_known_case():
    with pytest.raises(ValueError, match="word list needs at least"):
        g.generate_passphrase(["a", "b", "c"], PassphraseSettings())
    with pytest.raises(ValueError, match="at least 4 words"):
        g.generate_passphrase(WORDS, PassphraseSettings(words=3))
    with pytest.raises(ValueError, match="unknown word case"):
        g.generate_passphrase(WORDS, PassphraseSettings(case="shout"))


# --- the command line ---------------------------------------------------------------------------------------------------

def run(*args):
    result = CliRunner().invoke(app, ["generate", *args, "-f", "json"])
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout)


def test_the_defaults_make_a_password_of_letters_and_digits():
    data = run()
    assert len(data["value"]) == 20 and data["value"].isalnum() and data["entropy_bits"] > 100


def test_the_knobs_have_keepassxc_clis_names():
    p = run("--length", "30", "--no-lower", "--no-upper", "--numeric")["value"]
    assert len(p) == 30 and p.isdigit()
    s = run("-L", "16", "--special", "--no-numeric")["value"]
    assert len(s) == 16 and not any(c.isdigit() for c in s) and any(c in "".join(g.GROUPS[n] for n in g.SPECIAL) for c in s)


def test_exclude_and_include_and_the_two_flags_work_from_the_command_line():
    assert not set(run("-L", "40", "--exclude", "abcdef")["value"]) & set("abcdef")
    assert "#" in run("-L", "12", "--include", "#")["value"]
    assert set(run("-L", "300", "--no-exclude-similar")["value"]) & set("0Ol1I")


def test_a_setting_that_cannot_make_a_password_is_refused_with_the_reason():
    result = CliRunner().invoke(app, ["generate", "--no-lower", "--no-upper", "--no-numeric"])
    assert result.exit_code == 2 and "no character group is selected" in result.stderr


def test_a_passphrase_command_takes_count_separator_and_case(tmp_path):
    f = tmp_path / "words.txt"
    f.write_text("\n".join(WORDS), encoding="utf-8")
    phrase = run("--passphrase", "--words", str(f), "--count", "5", "--separator", "+", "--case", "upper")["value"]
    assert len(phrase.split("+")) == 5 and phrase.replace("+", "").isupper()
