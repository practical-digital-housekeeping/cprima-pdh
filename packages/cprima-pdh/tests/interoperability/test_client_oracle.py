"""Does a real client's engine read what pdh writes? KeePassXC's own `keepassxc-cli` is the checker (`just test-interoperability`).

Test-only and read-only: pdh writes a vault, KeePassXC opens it and reports what it sees. Nothing of KeePassXC is part of
the product, and the tests are skipped when it is not installed. Passwords are throwaway and every entry is invented.
"""
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from pdh_testkit import DEFAULT_PASSWORD, vaults
from pdh_testkit.cheap import cheap_copy
from pdh_testkit.mess import messy_vault
from typer.testing import CliRunner

from cprima_pdh import otp
from cprima_pdh.cli import _common, app
from cprima_pdh.source import pykeepass_open

KPX = shutil.which("keepassxc-cli") or r"C:\Program Files\KeePassXC\keepassxc-cli.exe"
pytestmark = [pytest.mark.interoperability,
              pytest.mark.skipif(not Path(KPX).exists(), reason="KeePassXC (keepassxc-cli) is not installed")]
SECRET = "JBSWY3DPEHPK3PXP"


def kpx(command, db, password, *positional, options=(), ok=True):
    """Run one read-only keepassxc-cli command; returns stdout. With ok=False returns (exit code, stdout)."""
    result = subprocess.run([KPX, command, "-q", *options, str(db), *positional], input=password + "\n",
                            capture_output=True, text=True, encoding="utf-8", timeout=120)
    if not ok:
        return result.returncode, result.stdout
    assert result.returncode == 0, f"keepassxc-cli {command} failed: {result.stderr or result.stdout}"
    return result.stdout


def listing(db, password):
    return set(kpx("ls", db, password, options=("-R", "-f")).split("\n")) - {""}


@pytest.fixture
def vault(tmp_path, monkeypatch):
    path = messy_vault(tmp_path / "m.kdbx").path
    state = {"password": DEFAULT_PASSWORD}
    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, state["password"], None))

    class V:
        path_ = path
        password = property(lambda self: state["password"])

        def set_password(self, value):
            state["password"] = value

        def pdh(self, *args, env=None, input=None):
            result = CliRunner().invoke(app, ["--db", str(path), *args], env=env, input=input)
            assert result.exit_code == 0, f"pdh {' '.join(args)}: {result.output}{result.stderr or ''}"

        def show(self, entry, *options):
            return kpx("show", path, self.password, entry, options=options)

    return V()


def test_the_client_reads_the_messy_vault_pdh_style_tests_build(vault):
    paths = listing(vault.path_, vault.password)
    assert {"Money/With history", "Money/Tagged", "Other/Soon", "Recycle Bin/In the bin"} <= paths
    assert "Deep/Deeper/Deepest/Bottom/Floor/Deep entry" in paths


def test_fields_tags_and_protection_written_by_pdh_are_read_back(vault):
    vault.pdh("edit", "set", "Money/Tagged", "Notes", "hello from pdh", "--apply")
    vault.pdh("edit", "set", "Money/Tagged", "token", "-", "--protect", "--apply", input="abc\n")
    vault.pdh("edit", "tags", "Money/Tagged", "--add", "four", "--remove", "one", "--apply")
    shown = vault.show("Money/Tagged")
    assert "Notes: hello from pdh" in shown and "Password: PROTECTED" in shown
    tags = [line for line in shown.splitlines() if line.startswith("Tags:")][0]
    assert set(tags.removeprefix("Tags:").strip().split(",")) == {"two", "three", "four"}
    assert vault.show("Money/Tagged", "-s", "-a", "token").strip() == "abc"


def test_a_one_time_password_gives_the_same_code_in_the_client(vault):
    vault.pdh("edit", "set", "Money/Tagged", "otp", "-", "--apply", input=f"otpauth://totp/x?secret={SECRET}&digits=6\n")  # a secret: prompt, not argv
    params = otp.parse(f"otpauth://totp/x?secret={SECRET}&digits=6")
    for _ in range(3):  # a retry if the 30-second window changes between the two readings
        before = otp.code(params).code
        theirs = vault.show("Money/Tagged", "-t").strip()
        after = otp.code(params).code
        if theirs in (before, after):
            return
        time.sleep(1)
    pytest.fail(f"KeePassXC shows {theirs}, pdh computes {before}/{after}")


def test_a_vault_that_needs_a_key_file_is_written_by_pdh_and_read_back_by_the_client_with_it(tmp_path, monkeypatch):
    """The genuine KeePassXC vault and key file: pdh opens it, changes it, and KeePassXC still opens it only with both."""
    fixture = vaults.load("keyfile-kdbx4")
    db, key = tmp_path / "g.kdbx", tmp_path / "g.keyx"
    shutil.copyfile(fixture.path, db)
    shutil.copyfile(fixture.keyfile, key)
    env = {"KDBX_PASSWORD": fixture.password, "KDBX_KEY": str(key)}
    for command in (["edit", "new-group", "/", "Shops"], ["edit", "new-entry", "Shops", "site", "alex", "--url", "https://s.example.org"],
                    ["edit", "fill", "Shops/site", "--generate"]):
        result = CliRunner().invoke(app, ["--db", str(db), *command, "--apply"], env=env)
        assert result.exit_code == 0, f"{command}: {result.stderr}"
    assert "Shops/site" in listing_with_key(db, fixture.password, key)
    shown = kpx("show", db, fixture.password, "Shops/site", options=("-k", str(key), "-s"))
    assert "UserName: alex" in shown and "URL: https://s.example.org" in shown
    password = [line for line in shown.splitlines() if line.startswith("Password:")][0].removeprefix("Password:").strip()
    assert len(password) == 20  # generated by pdh, stored, and the client reads it
    assert kpx("ls", db, fixture.password, ok=False)[0] != 0  # without the key file the client refuses it too


def listing_with_key(db, password, key):
    return set(kpx("ls", db, password, options=("-R", "-f", "-k", str(key))).split("\n")) - {""}


def test_attachments_are_read_byte_for_byte(vault, tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(bytes(range(40, 90)))
    vault.pdh("edit", "attach", "Money/Tagged", str(f), "--apply")
    out = subprocess.run([KPX, "attachment-export", "-q", "--stdout", str(vault.path_), "Money/Tagged", "f.bin"],
                         input=(vault.password + "\n").encode(), capture_output=True, timeout=120)  # bytes: binary output
    assert out.returncode == 0 and out.stdout == bytes(range(40, 90))


def test_the_recycle_bin_groups_and_moves_are_understood(vault):
    vault.pdh("edit", "delete", "Money/Tagged", "--apply")
    assert "Recycle Bin/Tagged" in listing(vault.path_, vault.password)
    vault.pdh("edit", "restore", "Recycle Bin/Tagged", "--to", "Other", "--apply")
    vault.pdh("edit", "new-group", "/", "Archive", "--apply")
    vault.pdh("edit", "rename-group", "Archive", "Old", "--apply")
    vault.pdh("edit", "move-group", "Old", "Other", "--cross-top-level", "--apply")
    vault.pdh("edit", "move", "Other/Tagged", "Other/Old", "--apply")
    paths = listing(vault.path_, vault.password)
    assert "Other/Old/Tagged" in paths and "Recycle Bin/Tagged" not in paths
    vault.pdh("edit", "delete-group", "Other/Old", "--apply")
    assert "Recycle Bin/Old/Tagged" in listing(vault.path_, vault.password)
    vault.pdh("db", "empty-bin", "--apply")
    paths = listing(vault.path_, vault.password)  # (an empty group is listed with a localized placeholder: not asserted)
    assert "Recycle Bin/Old/Tagged" not in paths and "Recycle Bin/In the bin" not in paths


def test_a_new_entry_with_everything_in_one_call_is_read_back(vault):
    vault.pdh("edit", "new-entry", "Other", "Created", "carol", "--url", "https://c.example.org", "--notes", "n",
              "--tag", "t1", "--field", "account_no=4711", "--apply")
    vault.pdh("edit", "set", "Other/Created", "Password", "-", "--apply", input="pw-created\n")
    vault.pdh("edit", "set", "Other/Created", "tok", "-", "--protect", "--apply", input="secret-tok\n")
    shown = vault.show("Other/Created", "-s")
    assert "UserName: carol" in shown and "Password: pw-created" in shown and "URL: https://c.example.org" in shown
    assert vault.show("Other/Created", "-a", "account_no").strip() == "4711"
    assert vault.show("Other/Created", "-s", "-a", "tok").strip() == "secret-tok"


def test_a_changed_master_password_and_a_copy_open_in_the_client(vault, tmp_path):
    vault.pdh("db", "password", "--apply", env={"PDH_NEW_PASSWORD": "second-pw"})
    vault.set_password("second-pw")
    assert "Money/Tagged" in listing(vault.path_, "second-pw")
    assert kpx("ls", vault.path_, DEFAULT_PASSWORD, ok=False)[0] != 0  # the old password no longer opens it
    copy = tmp_path / "copy.kdbx"
    vault.pdh("io", "export-kdbx", "--out", str(copy), env={"PDH_NEW_PASSWORD": "copy-pw"})
    assert "Money/Tagged" in listing(copy, "copy-pw")


def test_an_imported_vault_and_a_merge_are_read_back(vault, tmp_path):
    other = messy_vault(tmp_path / "other.kdbx").path
    vault.pdh("io", "import-kdbx", str(other), "--group", "Imported", "--apply", env={"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD})
    assert "Imported/Money/With attachments" in listing(vault.path_, vault.password)
    twin = tmp_path / "twin.kdbx"
    shutil.copyfile(vault.path_, twin)
    twin_kp = pykeepass_open(twin, DEFAULT_PASSWORD, None)
    entry = next(e for e in twin_kp.entries if e.title == "Soon")
    entry.notes = "edited in the copy"
    entry.touch(modify=True)
    twin_kp.save()
    vault.pdh("io", "merge", str(twin), "--apply", env={"PDH_IMPORT_PASSWORD": DEFAULT_PASSWORD})
    assert "Notes: edited in the copy" in vault.show("Other/Soon")


@pytest.mark.compatibility
@pytest.mark.parametrize("template", [v.name for v in vaults.all_vaults() if v.name.startswith("template-")])
def test_the_genuine_templates_edited_by_pdh_still_open_in_the_client(template, tmp_path, monkeypatch):
    """KDBX 3.1 and 4.0 written by KeePassXC itself, edited by pdh, read by KeePassXC again."""
    t = vaults.load(template)
    db = tmp_path / "work.kdbx"
    cheap_copy(template, db)  # the genuine template; its slow key derivation is lowered (see pdh_testkit.cheap)
    monkeypatch.setattr(_common, "open_db", lambda path, _key: pykeepass_open(path, t.password, None))

    def pdh(*args, env=None):
        result = CliRunner().invoke(app, ["--db", str(db), *args], env=env)
        assert result.exit_code == 0, f"pdh {' '.join(args)}: {result.output}{result.stderr or ''}"

    pdh("edit", "new-group", "/", "Money", "--apply")
    pdh("edit", "new-entry", "Money", "a", "alex", "--tag", "x", "--field", "k=v", "--apply")
    pdh("edit", "tags", "Money/a", "--add", "y", "--apply")
    pdh("edit", "set", "Money/a", "Notes", "hi", "--apply")
    pdh("edit", "delete", "Money/a", "--apply")
    pdh("edit", "restore", "Recycle Bin/a", "--to", "Money", "--apply")
    assert "Money/a" in listing(db, t.password)
    shown = kpx("show", db, t.password, "Money/a")
    assert "UserName: alex" in shown and "Notes: hi" in shown
