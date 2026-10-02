"""The showcase vault: a fictional, finished vault organised the way the profile `pdh-default` prescribes.

Three owners (two people and the shared records), the areas below them, and entries of every record type with
realistic fictional content: logins with TOTP, shops, bank and card records, keys, licences, contracts, a router with
its guest login (linked), memberships. Everything is fake (`example.org`, `192.0.2.x`, made-up numbers), protected as
the vocabulary demands, and the whole vault conforms to the profile.

Like the canonical vault it is a copy of the genuine KeePassXC template *filled by code with pykeepass*, so it is for
reading and for unit tests, not an end-to-end fixture. Regenerate with `just example` after changing a profile.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pykeepass import PyKeePass

from .paths import REPO_ROOT
from .vaults import load

NAME = "sample"
PASSWORD = "sample-test"
TEMPLATE = "template-kdbx4"
EXAMPLE_DIR = REPO_ROOT / "examples" / "pdh-default"
EXPIRY = datetime(2031, 12, 31, tzinfo=timezone.utc)

PERSON_A, PERSON_B, SHARED = "Alex", "Sam", "Shared"  # fictional owners: two people and the shared records
PW = "example-password"
TOTP = "otpauth://totp/Example:{who}?secret=JBSWY3DPEHPK3PXP&issuer=Example"


@dataclass(frozen=True)
class Item:
    owner: str
    area: str
    title: str
    schemas: str  # the `_schema` value; "" = none: the entry is typed by its fields alone (a profile match rule)
    std: dict = field(default_factory=dict)  # UserName, Password, URL, Notes
    fields: dict = field(default_factory=dict)  # custom fields (vocabulary terms)
    expires: bool = False
    totp: str = ""  # who the one-time-password belongs to ("" = none)
    link_to: str = ""  # title of the entry a `device` link points at


def login(host: str, user: str, pw: str = PW) -> dict:
    return {"UserName": user, "Password": pw, "URL": f"https://{host}.example.org/"}


ITEMS = [
    # --- Alex
    Item(PERSON_A, "Online & Communication", "Example Mail", "website", login("mail", "alex@example.org"), totp="alex"),
    Item(PERSON_A, "Online & Communication", "Example Social", "website", login("social", "alex")),
    Item(PERSON_A, "Online & Communication", "Example Domains", "website", login("domains", "alex@example.org"), totp="alex"),
    Item(PERSON_A, "Shopping", "Example Books", "onlineshop, website", login("books", "alex@example.org"),
         {"customer_no": "C-10442", "address": "Example Street 1\n00000 Example City", "phone": "+49 30 1234567"}),
    Item(PERSON_A, "Shopping", "Example Electronics", "onlineshop, website", login("electronics", "alex@example.org"),
         {"customer_no": "E-88120"}),
    Item(PERSON_A, "Money", "Example Bank Account", "", login("bank", "alex"),            # typed by its IBAN
         {"IBAN": "XX00 0000 0000 0000 00", "BIC": "EXAMPXXX", "account_number": "0000000001",   # three security questions
          "security_question_1": "Name of your first pet?", "security_answer_1": "example-answer-1",
          "security_question_2": "Street you grew up in?", "security_answer_2": "example-answer-2",
          "security_question_3": "Your favourite teacher?", "security_answer_3": "example-answer-3"}, totp="alex"),
    Item(PERSON_A, "Money", "Example Debit Card", "bank-card", {},
         {"card_number": "0000 0000 0000 0001", "PIN": "0000", "cardholder": "A. Example", "issuer": "Example Bank",
          "issuer_phone": "+49 30 7654321"}, expires=True),
    Item(PERSON_A, "Money", "Example Credit Card", "credit-card", {},                    # a CVV is never a rule: named
         {"card_number": "0000 0000 0000 0002", "PIN": "0000", "CVV": "000", "cardholder": "A. Example",
          "issuer": "Example Credit", "issuer_phone": "+49 30 7654322"}, expires=True),
    Item(PERSON_A, "Work", "Example Work Portal", "website", login("work", "alex@example.org"), totp="alex"),
    Item(PERSON_A, "Tech", "Example Git Host", "website", login("git", "alex"), totp="alex"),
    Item(PERSON_A, "Tech", "Deploy key example-server", "", {},                    # typed by its fingerprint
         {"fingerprint": "SHA256:EXAMPLEFINGERPRINT", "ssh_key": "example-private-key",
          "public_key": "ssh-ed25519 AAAAEXAMPLE"}),
    Item(PERSON_A, "Tech", "Example Cloud API", "", {},                            # typed by its api_key / client_id
         {"api_key": "example-api-key", "api_secret": "example-api-secret", "client_id": "example-client-id",
          "client_secret": "example-client-secret"}),
    Item(PERSON_A, "Tech", "Example Editor Licence", "software-license", {},
         {"license_key": "AAAAA-BBBBB-CCCCC", "serial_number": "SN-5521"}),
    Item(PERSON_A, "Identity & Authorities", "Passport", "identity-document", {}, {"valid_until": "2031-06-30"}),
    Item(PERSON_A, "Identity & Authorities", "Tax Portal", "website", login("tax", "alex"), totp="alex"),
    Item(PERSON_A, "Health", "Example Health Insurance", "utility-contract", {},
         {"customer_no": "H-3310", "contract_no": "K-2020-17", "phone": "+49 30 5550100", "email": "service@example.org"}),
    Item(PERSON_A, "Learning", "Example Courses", "website", login("courses", "alex@example.org")),
    Item(PERSON_A, "Learning", "Example Certification Body", "", {},                      # typed by its member_no
         {"member_no": "M-0042", "valid_until": "2029-03-31"}),
    Item(PERSON_A, "Travel & Mobility", "Example Rail Card", "membership", {},          # written and matched: counts once
         {"member_no": "R-7781", "valid_until": "2030-12-31"}),
    Item(PERSON_A, "Travel & Mobility", "Example Airline Miles", "website",              # written `website`, plus
         login("airline", "alex@example.org"), {"member_no": "A-99120"}),               # `membership` from its member_no
    Item(PERSON_A, "Leisure & Interests", "Example Streaming", "website", login("streaming", "alex@example.org")),
    Item(PERSON_A, "Leisure & Interests", "Example Gym", "membership", {}, {"member_no": "G-1500", "valid_until": "2030-06-30"}),
    Item(PERSON_A, "Home & Utilities", "Example Mobile Plan", "", {},                      # typed by its PUK
         {"phone": "+49 171 0000001", "PIN": "0000", "PUK": "00000000", "ICCID": "0000000000000000001",
          "carrier": "Example Mobile", "contract_no": "K-5001"}),
    # --- Sam
    Item(PERSON_B, "Online & Communication", "Example Mail (Sam)", "website", login("mail", "sam@example.org"), totp="sam"),
    Item(PERSON_B, "Shopping", "Example Marketplace", "onlineshop, website", login("marketplace", "sam@example.org"),
         {"customer_no": "S-20991"}),
    Item(PERSON_B, "Money", "Example Savings Bank", "bank-account", login("savings", "sam"),
         {"IBAN": "XX00 0000 0000 0000 01", "BIC": "EXAMPXXX"}, totp="sam"),
    Item(PERSON_B, "Money", "Example Debit Card (Sam)", "bank-card", {},
         {"card_number": "0000 0000 0000 0003", "PIN": "0000", "cardholder": "S. Example", "issuer": "Example Savings"},
         expires=True),
    Item(PERSON_B, "Tech", "Example Design Tool Licence", "software-license", {}, {"license_key": "DDDDD-EEEEE-FFFFF"}),
    # --- Shared: the home network and the contracts both people rely on
    # a router with Wi-Fi that runs OpenWrt: two written types whose requirements add up (Wi-Fi fields + SSH key)
    Item(SHARED, "Home & Utilities", "Home Router", "wifi-access-point, openwrt-device",
         {"UserName": "root", "Password": PW, "URL": "http://192.0.2.1/"},
         {"SSID": "example-network", "wifi_key": "example-wifi-key", "serial_number": "SN-0001",
          "MAC": "00:00:5E:00:53:01", "ssh_key": "example-private-key"}),
    Item(SHARED, "Home & Utilities", "Home Router: guest login", "",                    # typed by its `device` link
         {"UserName": "guest", "Password": PW, "URL": "http://192.0.2.1/"}, link_to="Home Router"),
    Item(SHARED, "Home & Utilities", "Office Access Point", "",                           # typed by its SSID
         {"UserName": "root", "Password": PW, "URL": "http://192.0.2.2/"},
         {"SSID": "example-office", "wifi_key": "example-office-key", "serial_number": "SN-0002",
          "MAC": "00:00:5E:00:53:02"}),
    Item(SHARED, "Home & Utilities", "Home Server", "hardware",
         {}, {"serial_number": "SN-0003", "part_number": "PN-4400", "MAC": "00:00:5E:00:53:03"}),
    Item(SHARED, "Home & Utilities", "Hardware Security Key", "",                         # typed by its so_pin
         {}, {"serial_number": "SN-0004", "so_pin": "0000", "user_pin": "0000"}),
    Item(SHARED, "Home & Utilities", "Electricity Provider", "", {},                      # customer_no + contract_no
         {"customer_no": "P-7001", "contract_no": "K-7001", "phone": "+49 30 5550200", "email": "service@example.org"}),
    Item(SHARED, "Home & Utilities", "Internet Provider", "utility-contract", {},
         {"customer_no": "P-7002", "contract_no": "K-7002", "phone": "+49 30 5550300"}),
]


def build(dest: Path, sset, template: Path | None = None) -> Path:
    """Write the showcase vault to `dest` (a copy of the template, filled) and return `dest`."""
    from cprima_pdh.schema import lookup_term, make_ref, vocabulary_index

    src = load(TEMPLATE)
    shutil.copyfile(template or src.path, dest)
    kp = PyKeePass(str(dest), password=src.password)
    owners: dict[str, object] = {}
    areas: dict[tuple[str, str], object] = {}
    made: dict[str, object] = {}

    def group(owner: str, area: str):
        if owner not in owners:
            owners[owner] = kp.add_group(kp.root_group, owner)
        if (owner, area) not in areas:
            assert area in sset.areas, f"{area!r} is not an area of the profile"
            areas[(owner, area)] = kp.add_group(owners[owner], area)
        return areas[(owner, area)]

    exact, matchers = vocabulary_index(sset.fields)
    for item in sorted(ITEMS, key=lambda i: bool(i.link_to)):  # what is linked to comes first
        s = item.std
        e = kp.add_entry(group(item.owner, item.area), item.title, s.get("UserName", ""), s.get("Password", ""),
                         url=s.get("URL"), notes=s.get("Notes"))
        if item.schemas:  # none = typed by its fields alone
            e.set_custom_property(sset.binding.field, item.schemas)
        for name, value in item.fields.items():
            term = lookup_term(name, exact, matchers)  # a term by name or by name pattern (security_answer_1, ...)
            e.set_custom_property(name, value, protect=bool(term and term[1].protected is True))
        if item.link_to:
            e.set_custom_property("device", make_ref(made[item.link_to].uuid))
        if item.totp:
            e.otp = TOTP.format(who=item.totp)
        if item.expires:
            e.expiry_time, e.expires = EXPIRY, True
        made[item.title] = e
    kp.password = PASSWORD
    kp.save()
    return dest


def write_sidecar(dest: Path) -> Path:
    side = dest.with_suffix(".toml")
    side.write_text(
        f'# Sidecar of {dest.name}: the showcase vault. pdh reads the password from here, so it needs no prompt.\n'
        f'# A throwaway sample password; never use it for anything real.\n'
        f'password = "{PASSWORD}"\n'
        f'client = "KeePassXC"\n'
        f'format = "KDBX 4.0"\n'
        f'filled_by = "pdh-testkit showcase builder (pykeepass), on a copy of {TEMPLATE}.kdbx"\n'
        f'description = "Fictional vault organised by the profile pdh-default: three owners, every area, every record '
        f'type, all conforming. Regenerate with `just example`."\n',
        encoding="utf-8")
    return side


def main() -> None:
    from cprima_pdh import profiles

    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    dest = EXAMPLE_DIR / f"{NAME}.kdbx"
    build(dest, profiles.load(profiles.DEFAULT))
    write_sidecar(dest)
    print(f"wrote {dest} and {dest.with_suffix('.toml').name}")


if __name__ == "__main__":
    main()
