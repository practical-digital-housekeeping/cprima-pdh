"""Checks against what is known online: leaked passwords and breached sites. Names and counts only, never a secret.

- Known passwords: Have I Been Pwned's range API. Only the first 5 hex characters of each SHA-1 are sent (k-anonymity),
  with padding, so the service cannot tell which of the returned hashes was asked for. Or a local, sorted SHA-1 list.
- Breaches: the public breach catalogue is downloaded and compared with the entries' URLs locally; nothing from the vault
  is sent. Optionally (with a key) each e-mail address is looked up, which does send the addresses.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, urlparse

from . import net
from .conform import _issue
from .models import LEVEL_ORDER, AccountHit, BreachHit, BreachReport, KnownPassword, KnownPasswordsReport, RuleFinding
from .source import _aware, _gpath, _in_bin

if TYPE_CHECKING:
    from pykeepass import PyKeePass

RANGE_URL = "https://api.pwnedpasswords.com/range/"
CATALOGUE_URL = "https://haveibeenpwned.com/api/v3/breaches"
ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
ACCOUNT_PAUSE = 1.6  # seconds between account lookups: the service's rate limit for the cheapest key
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _judged(item, rule: str, sset, message: str):
    """The item with the profile's level and advice for `rule` filled in."""
    finding = RuleFinding(schema="online", entry=item.entry, rule=rule, level=sset.levels.of(rule), message=message)
    issue = _issue(finding, sset)
    return item.model_copy(update={"rule": rule, "level": issue.level, "action": issue.action, "note": issue.note})


def judge(report, sset):
    """Give every item of an online report its rule, level and advice from the profile (the engine decides nothing)."""
    if isinstance(report, KnownPasswordsReport):
        return report.model_copy(update={"exposed": [
            _judged(x, "known-password", sset, "the password appears in known leaks") for x in report.exposed]})
    hits = []
    for h in report.hits:
        if "Passwords" not in h.data_classes:
            rule = "breach:other"  # the breach did not leak passwords
        else:
            rule = "breach:changed" if h.changed_since else "breach:unchanged"
        hits.append(_judged(h, rule, sset, f"{h.domain} was breached on {h.breach_date}"))
    accounts = [_judged(a, "breach:account", sset, "the address appears in known breaches") for a in report.accounts]
    return report.model_copy(update={"hits": hits, "accounts": accounts})


def worst_level(report) -> int:
    """The highest `LEVEL_ORDER` among the items of an online report (0 when there are none)."""
    items = report.exposed if isinstance(report, KnownPasswordsReport) else [*report.hits, *report.accounts]
    return max((LEVEL_ORDER[i.level] for i in items), default=0)


def _live(kp: PyKeePass):
    rb = kp.recyclebin_group
    return [e for e in kp.entries if rb is None or not _in_bin(e.group, rb.uuid)]


def _sha1(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324 - the service's format, not security


def _by_hash(kp: PyKeePass) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in _live(kp):
        if e.password:
            out.setdefault(_sha1(e.password), []).append(f"{_gpath(e.group)}/{e.title}")
    return out


def _report(source: str, hashes: dict[str, list[str]], counts: dict[str, int]) -> KnownPasswordsReport:
    exposed = [KnownPassword(entry=path, count=counts[h]) for h, paths in hashes.items() if counts.get(h)
               for path in paths]
    return KnownPasswordsReport(source=source, checked=sum(len(p) for p in hashes.values()),
                                exposed=sorted(exposed, key=lambda x: x.entry))


def known_passwords_online(kp: PyKeePass) -> KnownPasswordsReport:
    """Ask the range API, once per distinct 5-character prefix."""
    hashes = _by_hash(kp)
    counts: dict[str, int] = {}
    for prefix in sorted({h[:5] for h in hashes}):
        body = net.fetch(RANGE_URL + prefix, headers={"Add-Padding": "true"}).decode("ascii", errors="replace")
        for line in body.splitlines():
            suffix, _, count = line.strip().partition(":")
            if suffix and count.isdigit() and int(count) > 0:
                counts[prefix + suffix.upper()] = int(count)  # padding rows have a count of 0 and are ignored
    return _report("online", hashes, counts)


def _lookup(f, size: int, key: bytes) -> int | None:
    """Binary search for `key` (40 upper-case hex characters) in a file of `HASH:COUNT` lines sorted by hash."""
    lo, hi = 0, size  # lo is always the start of a line
    while lo < hi:
        mid = (lo + hi) // 2
        f.seek(mid)
        if mid > lo:
            f.seek(mid - 1)
            if f.read(1) != b"\n":
                f.readline()  # inside a line: go on to the next line start
        start = f.tell()
        if start >= hi:
            hi = mid
            continue
        line = f.readline()
        found = line[:40].upper()
        if found == key:
            _, _, count = line.strip().partition(b":")
            return int(count) if count.isdigit() else 1
        if found < key:
            lo = f.tell()
        else:
            hi = mid
    return None


def known_passwords_file(kp: PyKeePass, file: Path) -> KnownPasswordsReport:
    """Look the hashes up in a local sorted SHA-1 list (the Pwned Passwords download); no network."""
    hashes = _by_hash(kp)
    counts: dict[str, int] = {}
    with open(file, "rb") as f:
        size = Path(file).stat().st_size
        for h in hashes:
            found = _lookup(f, size, h.encode("ascii"))
            if found:
                counts[h] = found
    return _report("file", hashes, counts)


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else "//" + url)
    host = (parsed.hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def breach_report(kp: PyKeePass, accounts: bool = False, api_key: str = "") -> BreachReport:
    """Compare the entries' sites with the public breach catalogue; optionally look up e-mail addresses."""
    catalogue = json.loads(net.fetch(CATALOGUE_URL).decode("utf-8"))
    with_domain = [(b, b["Domain"].strip().lower()) for b in catalogue if (b.get("Domain") or "").strip()]
    hits: list[BreachHit] = []
    live = _live(kp)
    for e in live:
        host = _host(e.url or "")
        if not host:
            continue
        modified = _aware(e.mtime) or datetime.min.replace(tzinfo=timezone.utc)
        for b, domain in with_domain:
            if host == domain or host.endswith("." + domain):
                when = date.fromisoformat(b["BreachDate"]) if b.get("BreachDate") else date.min
                hits.append(BreachHit(entry=f"{_gpath(e.group)}/{e.title}", breach=b["Name"], domain=domain,
                                      breach_date=when.isoformat(), data_classes=list(b.get("DataClasses") or []),
                                      changed_since=modified.date() >= when))
    found: list[AccountHit] = []
    if accounts:
        asked = False
        for e in live:
            address = (e.username or "").strip()
            if not _EMAIL.fullmatch(address):
                continue
            if asked:
                net.pause(ACCOUNT_PAUSE)
            asked = True
            try:
                body = net.fetch(ACCOUNT_URL + quote(address, safe="") + "?truncateResponse=true",
                                 headers={"hibp-api-key": api_key})
            except net.NetworkError as exc:
                if exc.status == 404:  # the address is in no known breach
                    continue
                raise
            names = [b["Name"] for b in json.loads(body.decode("utf-8"))]
            if names:
                found.append(AccountHit(entry=f"{_gpath(e.group)}/{e.title}", breaches=names))
    return BreachReport(catalogue=len(catalogue), hits=sorted(hits, key=lambda h: (h.entry, h.breach)), accounts=found)
