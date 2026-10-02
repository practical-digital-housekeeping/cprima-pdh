"""The Wi-Fi access point schema, against the public taxonomy.

A device (identifiers) plus a Wi-Fi network (name required, key recommended). The admin login is just the
standard URL/UserName/Password fields; a local http:// admin page is a valid URI and is not an issue.
The taxonomy is dogma: extra fields that are not vocabulary terms are reported as `unknown-field` (WARN).
"""
import pytest
from pdh_testkit.paths import TAXONOMY
from pdh_testkit.stubs import E, StubKP

from cprima_pdh.schema import load_schemas, validate

REAL = load_schemas(TAXONOMY)
UNKNOWN = ("vocabulary", "unknown-field", "WARN")
AP = "wifi-access-point"
KEY = ("wifi_key",)  # protected in KeePass


def ap(custom: dict[str, str], protected=KEY, schema: str = AP, **kw):
    return E(schema=schema, custom=custom, protected=protected, **kw)


# (case id, entry, expected {(schema, rule, level)})
CASES = [
    ("complete-access-point", ap({"SSID": "home", "wifi_key": "k"}), set()),
    ("with-device-identifiers", ap({"SSID": "home", "wifi_key": "k", "MAC": "aa:bb", "serial_number": "1"}), set()),
    ("without-a-network-name-is-an-error", ap({"wifi_key": "k"}), {(AP, "required:SSID", "ERROR")}),
    ("without-a-key-is-only-a-warning (open network)", ap({"SSID": "guest"}), {(AP, "recommended:wifi_key", "WARN")}),
    ("unprotected-key-is-a-warning", ap({"SSID": "home", "wifi_key": "k"}, protected=()),
     {("vocabulary", "protected:wifi_key", "WARN")}),
    ("other-spelling-is-not-the-key (only the secret pattern guards it)",
     ap({"SSID": "home", "wifikey": "k"}, protected=("wifikey",)), {(AP, "recommended:wifi_key", "WARN")}),
    ("local-http-admin-page-is-not-flagged", ap({"SSID": "home", "wifi_key": "k"}, url="http://192.168.1.1/"), set()),
    ("extra-field-is-not-closed-but-unsupported", ap({"SSID": "home", "wifi_key": "k", "port-forwarding": "x"}),
     {UNKNOWN}),
    ("the-ssid-needs-no-protection", ap({"SSID": "home", "wifi_key": "k"}, protected=("wifi_key", "SSID")), set()),
    ("also-a-website-http-admin-is-a-warning", ap({"SSID": "home", "wifi_key": "k"}, schema=f"{AP}, website",
                                                 url="http://192.168.1.1/"),
     {("website", "url:https", "WARN")}),
    # --- the admin login of an access point: recommended, never required -----------------------------------
    ("access-point-without-admin-password-is-a-warning", ap({"SSID": "home", "wifi_key": "k"}, password=""),
     {(AP, "recommended:Password", "WARN")}),
    ("access-point-without-admin-url-is-a-warning", ap({"SSID": "home", "wifi_key": "k"}, url=""),
     {(AP, "recommended:URL", "WARN")}),
    # --- OpenWrt: root over the web interface and SSH ------------------------------------------------------
    ("openwrt-access-point-with-ssh-key",
     ap({"SSID": "home", "wifi_key": "k", "ssh_key": "KEY"}, schema=f"{AP}, openwrt-device",
        protected=("wifi_key", "ssh_key")), set()),
    ("openwrt-with-password-login-only", ap({}, schema="openwrt-device", username="root"), set()),
    ("openwrt-ssh-key-must-be-protected", ap({"ssh_key": "KEY"}, schema="openwrt-device", protected=()),
     {("vocabulary", "protected:key_material", "WARN")}),
    ("openwrt-without-admin-password-is-a-warning", ap({}, schema="openwrt-device", password=""),
     {("openwrt-device", "recommended:Password", "WARN")}),
    ("openwrt-without-a-url-is-a-warning", ap({}, schema="openwrt-device", url=""),
     {("openwrt-device", "recommended:URL", "WARN")}),
    ("openwrt-is-not-closed-but-extra-fields-are-unsupported",
     ap({"port-forwarding": "x", "firmware": "23.05"}, schema="openwrt-device"), {UNKNOWN}),
    ("ssh-public-key-is-not-a-secret", ap({"ssh_pub": "ssh-ed25519 AAAA"}, schema="openwrt-device", protected=()),
     {UNKNOWN}),
]


@pytest.mark.parametrize("entry,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_access_point_findings(entry, expected):
    report = validate(StubKP([entry]), REAL)
    assert {(f.schema_name, f.rule, f.level) for f in report.findings} == expected


def test_it_is_composed_from_reusable_facets():
    schema = REAL.schemas[AP]
    assert schema.facets == ["device-core", "wifi-network", "admin-login"] and schema.family == "device"
    assert REAL.facets["wifi-network"].required == ["SSID"]
    assert REAL.facets["wifi-network"].recommended == ["wifi_key"]
    assert REAL.facets["device-core"].optional == ["serial_number", "MAC"]
    assert REAL.facets["admin-login"].recommended == ["URL", "UserName", "Password"]
    assert REAL.facets["ssh-access"].optional == ["ssh_key"]
    assert REAL.schemas["openwrt-device"].facets == ["device-core", "admin-login", "ssh-access"]


def test_the_terms_it_uses_are_real_vocabulary():
    for term in ("SSID", "wifi_key", "MAC", "serial_number"):
        assert term in REAL.fields, f"{term} must be an active vocabulary term"
