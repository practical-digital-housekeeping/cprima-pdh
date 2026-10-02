"""Synthetic vaults open fast and contain exactly what was asked for."""
import time
from datetime import datetime, timezone

from pykeepass import PyKeePass

from pdh_testkit import DEFAULT_PASSWORD, Entry


def test_opens_in_well_under_a_second(make_synthetic_vault):
    path = make_synthetic_vault([Entry("Shop A", group="Shopping", username="alice", password="pw")])
    start = time.perf_counter()
    kp = PyKeePass(str(path), password=DEFAULT_PASSWORD)
    assert time.perf_counter() - start < 0.5
    assert kp.version == (4, 0)


def test_groups_standard_and_custom_fields(make_synthetic_vault):
    path = make_synthetic_vault(
        [Entry("Router", group="Home/Network", username="root", password="pw", url="http://192.0.2.1",
               custom={"_schema": "openwrt-device", "PIN": "1234"}, protected=frozenset({"PIN"}), tags=("lab",))],
        groups=["Empty"],
    )
    kp = PyKeePass(str(path), password=DEFAULT_PASSWORD)
    e = kp.find_entries(title="Router", first=True)
    assert "/".join(e.group.path) == "Home/Network"
    assert (e.username, e.password, e.url, e.tags) == ("root", "pw", "http://192.0.2.1", ["lab"])
    assert e.get_custom_property("_schema") == "openwrt-device"
    assert e._element.xpath("boolean(String[Key='PIN']/Value[@Protected='True'])")
    assert not e._element.xpath("boolean(String[Key='_schema']/Value[@Protected='True'])")
    assert kp.find_groups(name="Empty", first=True) is not None


def test_expiry(make_synthetic_vault):
    when = datetime(2027, 1, 31, tzinfo=timezone.utc)
    path = make_synthetic_vault([Entry("Card", expires=when), Entry("No expiry")])
    kp = PyKeePass(str(path), password=DEFAULT_PASSWORD)
    card, other = kp.find_entries(title="Card", first=True), kp.find_entries(title="No expiry", first=True)
    assert card.expires and card.expiry_time.date() == when.date()
    assert not other.expires
