"""`check known-passwords` and `check breaches`. The network is replaced by a fake: no test touches the internet."""
import hashlib
import json
import re
from datetime import datetime, timezone

import pytest
from pdh_testkit import DEFAULT_PASSWORD, Entry, synthetic_vault
from pykeepass import PyKeePass
from typer.testing import CliRunner

from cprima_pdh import net
from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest().upper()


class FakeNet:
    """Records every request; answers from a table of url -> bytes."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, url, headers=None, timeout=15):
        self.calls.append((url, dict(headers or {})))
        if url in self.answers:
            return self.answers[url]
        raise net.NetworkError(f"not found: {url}", status=404)


@pytest.fixture(autouse=True)
def opens_with_the_test_password(monkeypatch):
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))
    monkeypatch.setattr(net, "pause", lambda seconds: None)  # no real waiting between account lookups


def use(monkeypatch, answers):
    fake = FakeNet(answers)
    monkeypatch.setattr(net, "fetch", fake)
    return fake


def invoke(vault, *args, env=None):
    return CliRunner().invoke(app, ["--db", str(vault), *args], env=env)


# --- known passwords -----------------------------------------------------------------------------------------------

@pytest.fixture
def vault(tmp_path):
    return synthetic_vault(tmp_path / "v.kdbx", [
        Entry("one", group="G", password="password"),
        Entry("two", group="G", password="password"),  # the same weak password twice
        Entry("unique", group="G", password="Zq9!never-seen-before-4711"),
        Entry("empty", group="G", password=""),
    ])


def range_answer(password, count):
    h = sha1(password)
    return {f"https://api.pwnedpasswords.com/range/{h[:5]}": f"{h[5:]}:{count}\r\n0000000000000000000000000000000000A:0\r\n".encode()}


def test_it_refuses_to_look_anything_up_without_online_or_a_hash_file(vault, monkeypatch):
    fake = use(monkeypatch, {})
    result = invoke(vault, "check", "known-passwords")
    assert result.exit_code == 2 and fake.calls == []


def test_online_it_sends_only_five_characters_of_each_hash_and_asks_for_padding(vault, monkeypatch):
    fake = use(monkeypatch, {**range_answer("password", 3861493),
                             **{f"https://api.pwnedpasswords.com/range/{sha1('Zq9!never-seen-before-4711')[:5]}": b""}})
    result = invoke(vault, "check", "known-passwords", "--online", "-f", "json")
    assert all(re.fullmatch(r"https://api\.pwnedpasswords\.com/range/[0-9A-F]{5}", u) for u, _ in fake.calls)
    assert len(fake.calls) == 2  # one per distinct prefix: the repeated password is asked once
    assert all(h.get("Add-Padding") == "true" for _, h in fake.calls)
    data = json.loads(result.stdout)
    assert result.exit_code == 1 and data["source"] == "online" and data["checked"] == 3  # the empty password is skipped
    assert sorted(e["entry"] for e in data["exposed"]) == ["G/one", "G/two"]
    assert all(e["count"] == 3861493 for e in data["exposed"])


def test_the_report_never_contains_a_password_or_a_hash(vault, monkeypatch):
    use(monkeypatch, {**range_answer("password", 5),
                      f"https://api.pwnedpasswords.com/range/{sha1('Zq9!never-seen-before-4711')[:5]}": b""})
    out = invoke(vault, "check", "known-passwords", "--online", "-f", "json").stdout
    assert sha1("password")[5:] not in out and sha1("password")[:5] not in out and "Zq9!" not in out


def test_nothing_exposed_exits_0(vault, monkeypatch, tmp_path):
    use(monkeypatch, {f"https://api.pwnedpasswords.com/range/{sha1(p)[:5]}": b"" for p in ("password", "Zq9!never-seen-before-4711")})
    assert invoke(vault, "check", "known-passwords", "--online").exit_code == 0


def test_the_recycle_bin_is_not_checked(tmp_path, monkeypatch):
    db = synthetic_vault(tmp_path / "b.kdbx", [Entry("live", group="G", password="Zq9!never-seen-before-4711"),
                                              Entry("dead", group="G", password="password")])
    kp = PyKeePass(str(db), password=DEFAULT_PASSWORD)
    kp.trash_entry(next(e for e in kp.entries if e.title == "dead"))
    kp.save()
    fake = use(monkeypatch, {f"https://api.pwnedpasswords.com/range/{sha1('Zq9!never-seen-before-4711')[:5]}": b""})
    assert invoke(db, "check", "known-passwords", "--online").exit_code == 0 and len(fake.calls) == 1


def test_a_local_sorted_hash_file_is_searched_without_the_network(vault, monkeypatch, tmp_path):
    fake = use(monkeypatch, {})
    lines = sorted([f"{sha1('password')}:42", f"{sha1('other')}:7", "0" * 40 + ":1", "F" * 40 + ":2"])
    f = tmp_path / "hashes.txt"
    f.write_text("\n".join(lines) + "\n", encoding="ascii")
    data = json.loads(invoke(vault, "check", "known-passwords", "--hashes", str(f), "-f", "json").stdout)
    assert fake.calls == [] and data["source"] == "file"
    assert sorted((e["entry"], e["count"]) for e in data["exposed"]) == [("G/one", 42), ("G/two", 42)]


def test_a_network_failure_is_a_clean_refusal_not_a_traceback(vault, monkeypatch):
    def boom(url, headers=None, timeout=15):
        raise net.NetworkError("could not connect")

    monkeypatch.setattr(net, "fetch", boom)
    result = invoke(vault, "check", "known-passwords", "--online")
    assert result.exit_code == 2 and "could not connect" in result.stderr


# --- breaches ---------------------------------------------------------------------------------------------------------

CATALOGUE = json.dumps([
    {"Name": "ExampleBreach", "Title": "Example", "Domain": "example.org", "BreachDate": "2020-01-01",
     "DataClasses": ["Email addresses", "Passwords"]},
    {"Name": "NoDomain", "Title": "No domain", "Domain": "", "BreachDate": "2019-01-01", "DataClasses": ["Passwords"]},
]).encode()
CATALOGUE_URL = "https://haveibeenpwned.com/api/v3/breaches"


@pytest.fixture
def sites(tmp_path):
    db = synthetic_vault(tmp_path / "s.kdbx", [
        Entry("before", group="G", url="https://www.example.org/login", username="user@example.org"),
        Entry("after", group="G", url="https://sub.example.org/"),
        Entry("lookalike", group="G", url="https://notexample.org/"),
        Entry("nourl", group="G"),
    ])
    kp = PyKeePass(str(db), password=DEFAULT_PASSWORD)
    for title, when in (("before", datetime(2019, 6, 1, tzinfo=timezone.utc)), ("after", datetime(2021, 6, 1, tzinfo=timezone.utc))):
        next(e for e in kp.entries if e.title == title).mtime = when
    kp.save()
    return db


def test_breaches_refuses_without_online(sites, monkeypatch):
    fake = use(monkeypatch, {CATALOGUE_URL: CATALOGUE})
    assert invoke(sites, "check", "breaches").exit_code == 2 and fake.calls == []


def test_breaches_matches_domains_locally_and_sends_nothing_from_the_vault(sites, monkeypatch):
    fake = use(monkeypatch, {CATALOGUE_URL: CATALOGUE})
    result = invoke(sites, "check", "breaches", "--online", "-f", "json")
    data = json.loads(result.stdout)
    assert [c[0] for c in fake.calls] == [CATALOGUE_URL]  # one request, the public catalogue
    hits = {h["entry"]: h for h in data["hits"]}
    assert set(hits) == {"G/before", "G/after"}  # not the look-alike domain, not the entry without a URL
    assert hits["G/before"]["changed_since"] is False and hits["G/after"]["changed_since"] is True
    assert hits["G/before"]["breach"] == "ExampleBreach" and "Passwords" in hits["G/before"]["data_classes"]
    assert hits["G/before"]["breach_date"] == "2020-01-01"
    assert result.exit_code == 1  # an entry not changed since a breach that leaked passwords


def test_nothing_unchanged_since_a_breach_exits_0(sites, monkeypatch):
    kp = PyKeePass(str(sites), password=DEFAULT_PASSWORD)
    next(e for e in kp.entries if e.title == "before").mtime = datetime(2022, 1, 1, tzinfo=timezone.utc)
    kp.save()
    use(monkeypatch, {CATALOGUE_URL: CATALOGUE})
    assert invoke(sites, "check", "breaches", "--online").exit_code == 0


def test_account_lookup_needs_a_key_and_sends_only_the_addresses(sites, monkeypatch):
    fake = use(monkeypatch, {CATALOGUE_URL: CATALOGUE,
                             "https://haveibeenpwned.com/api/v3/breachedaccount/user%40example.org?truncateResponse=true":
                                 json.dumps([{"Name": "Leak1"}, {"Name": "Leak2"}]).encode()})
    assert invoke(sites, "check", "breaches", "--online", "--accounts").exit_code == 2  # no HIBP_API_KEY
    result = invoke(sites, "check", "breaches", "--online", "--accounts", "-f", "json", env={"HIBP_API_KEY": "k-123"})
    data = json.loads(result.stdout)
    lookups = [(u, h) for u, h in fake.calls if "breachedaccount" in u]
    assert len(lookups) == 1 and lookups[0][1].get("hibp-api-key") == "k-123"
    assert [(a["entry"], a["breaches"], a["rule"], a["level"]) for a in data["accounts"]] == [
        ("G/before", ["Leak1", "Leak2"], "breach:account", "WARN")]
    assert "k-123" not in result.stdout


def test_an_address_in_no_breach_is_not_a_hit(sites, monkeypatch):
    use(monkeypatch, {CATALOGUE_URL: CATALOGUE})  # the account URL answers 404: not in any breach
    data = json.loads(invoke(sites, "check", "breaches", "--online", "--accounts", "-f", "json",
                             env={"HIBP_API_KEY": "k"}).stdout)
    assert data["accounts"] == []


# --- level and advice come from the profile -------------------------------------------------------------------------

def test_known_password_findings_carry_the_profile_level_and_advice(vault, monkeypatch):
    use(monkeypatch, {**range_answer("password", 5),
                      f"https://api.pwnedpasswords.com/range/{sha1('Zq9!never-seen-before-4711')[:5]}": b""})
    data = json.loads(invoke(vault, "check", "known-passwords", "--online", "-f", "json").stdout)
    first = data["exposed"][0]
    assert (first["rule"], first["level"], first["action"]) == ("known-password", "ERROR", "change-password")
    assert "G/one" not in first["note"] and "5BAA6" not in first["note"]  # advice text, never data


def test_breach_findings_carry_the_rule_that_the_data_selects(sites, monkeypatch):
    use(monkeypatch, {CATALOGUE_URL: CATALOGUE})
    hits = {h["entry"]: h for h in json.loads(invoke(sites, "check", "breaches", "--online", "-f", "json").stdout)["hits"]}
    assert (hits["G/before"]["rule"], hits["G/before"]["level"]) == ("breach:unchanged", "ERROR")
    assert (hits["G/after"]["rule"], hits["G/after"]["level"]) == ("breach:changed", "INFO")


def test_a_taxonomy_decides_the_severity_and_so_the_exit_code(sites, monkeypatch, tmp_path):
    """The same data, two taxonomies: only the profile's levels differ, and with them the exit code."""
    use(monkeypatch, {CATALOGUE_URL: CATALOGUE})
    lenient = tmp_path / "lenient.toml"
    lenient.write_text('[level]\ndefault = "INFO"\n"breach:unchanged" = "WARN"\n', encoding="utf-8")
    args = ["--schemas", str(lenient), "check", "breaches", "--online"]
    assert invoke(sites, *args).exit_code == 0  # WARN is below the default --fail-on ERROR
    assert invoke(sites, *args, "--fail-on", "WARN").exit_code == 1
    assert invoke(sites, "check", "breaches", "--online").exit_code == 1  # pdh-default says ERROR
