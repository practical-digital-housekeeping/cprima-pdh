"""Which tests run: the default is the fast set; the expensive sets are opted into by marker.

Markers (`pyproject.toml` lists them and excludes both from the default run):
- `compatibility`    the same behaviour across every genuine KeePassXC template (KDBX versions, ciphers, key derivations).
                     Set here on every test under `tests/compatibility/` and on any test whose id names a template. One open
                     of the AES-KDF template alone takes minutes.
- `interoperability` an independently built program (keepassxc-cli, sops, age) reads or checks what pdh wrote.
                     Set here on every test under `tests/interoperability/`; single tests elsewhere carry the marker themselves.

The words are the usual ones from the testing literature; see `packages/cprima-pdh/tests/TESTING.md`.
Pick an area with pytest's own selection: a path, `-k sops`, or `-m compatibility`.
"""
import pytest


@pytest.fixture(autouse=True)
def never_the_real_session(monkeypatch, tmp_path):
    """Every pdh call looks at the session file, and an expired one is deleted: no test may reach the owner's real one."""
    from cprima_pdh import session

    monkeypatch.setattr(session, "SESSION_FILE", tmp_path / "session-for-tests.bin")


@pytest.fixture
def opens_with_the_test_password(monkeypatch):
    """The CLI opens a vault with the testkit's throwaway password instead of asking for one."""
    from pdh_testkit import DEFAULT_PASSWORD

    from cprima_pdh.cli import _common
    from cprima_pdh.source import pykeepass_open

    monkeypatch.setattr(_common, "open_db", lambda db, _key: pykeepass_open(db, DEFAULT_PASSWORD, None))


TEMPLATE_ID = "template-"  # the id of a test parametrised over the genuine templates


def pytest_collection_modifyitems(items):
    for item in items:
        directories = {part for part in item.path.parts}
        if "compatibility" in directories or TEMPLATE_ID in item.nodeid:
            item.add_marker(pytest.mark.compatibility)
        if "interoperability" in directories:
            item.add_marker(pytest.mark.interoperability)
