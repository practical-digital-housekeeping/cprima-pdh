"""Genuine vaults: made by keepassxc-cli and read back by keepassxc-cli. Skipped without KeePassXC."""
import pytest
from pykeepass import PyKeePass

from pdh_testkit import DEFAULT_PASSWORD

pytestmark = pytest.mark.e2e


def test_keepassxc_creates_and_reads_back(keepassxc, tmp_path):
    db = keepassxc.create(tmp_path / "genuine.kdbx")
    keepassxc.mkdir(db, "Shopping")
    keepassxc.add(db, "Shopping/Shop A", username="alice", url="http://shop.example", entry_password="entry-pw")
    assert keepassxc.show(db, "Shopping/Shop A") == {
        "Title": "Shop A", "UserName": "alice", "URL": "http://shop.example"}


def test_a_genuine_vault_is_kdbx_3_1_and_readable_by_pykeepass(keepassxc, tmp_path):
    db = keepassxc.create(tmp_path / "genuine.kdbx")
    keepassxc.add(db, "Entry", username="bob", entry_password="secret")
    kp = PyKeePass(str(db), password=DEFAULT_PASSWORD)
    assert kp.version == (3, 1)  # keepassxc-cli 2.7 writes KDBX 3.1; KDBX 4 comes from committed client files
    assert [(e.title, e.username, e.password) for e in kp.entries] == [("Entry", "bob", "secret")]


def test_passwords_never_reach_the_command_line(keepassxc, tmp_path, monkeypatch):
    import subprocess

    seen = []
    real = subprocess.run
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: (seen.append(args), real(args, **kw))[1])
    db = keepassxc.create(tmp_path / "genuine.kdbx")
    keepassxc.add(db, "Entry", entry_password="entry-secret")
    flat = " ".join(" ".join(a) for a in seen)
    assert DEFAULT_PASSWORD not in flat and "entry-secret" not in flat
