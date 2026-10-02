"""Reads a KDBX file (via pykeepass) into pdh models. Never saves."""
from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # pykeepass is the optional `kdbx` extra
    from pykeepass import PyKeePass

from .models import (
    DbMeta,
    DuplicateStats,
    EntryDetail,
    EntryRecord,
    ExpiryStats,
    FieldStats,
    GroupNode,
    Inventory,
    QualityStats,
    StructureStats,
)
from .session import load_session

_OTP_PREFIXES = (("TimeOtp-", "TimeOtp"), ("HmacOtp-", "HmacOtp"))


class OpenError(Exception):
    pass


def pykeepass_open(path: str | Path, password: str | None, keyfile: str | None) -> PyKeePass:
    """The one place that constructs a PyKeePass; imported here so pykeepass stays optional."""
    from pykeepass import PyKeePass

    return PyKeePass(str(path), password=password, keyfile=keyfile)


def open_db(path: Path, key: Path | None, prompt: Callable[[], str | None]) -> PyKeePass:
    """Open db using the session cache if valid, else prompt() for the password."""
    sess = load_session(path)
    if sess:
        password, sess_key = sess
        keyfile = str(key) if key else sess_key
    else:
        password, keyfile = prompt(), (str(key) if key else None)
    try:
        return pykeepass_open(path, password, keyfile)
    except Exception as exc:  # wrong credentials, corrupt file, ...
        raise OpenError(str(exc)) from exc


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _gpath(group) -> str:
    p = group.path
    if isinstance(p, (list, tuple)):
        p = "/".join(p)
    return p or "/"


def _totp_style(entry, props: dict) -> str | None:
    if entry.otp:  # pykeepass reserves "otp", so it is not in custom_properties
        return "otp"
    for prefix, style in _OTP_PREFIXES:
        if any(k.startswith(prefix) for k in props):
            return style
    return None


def _in_bin(group, bin_uuid) -> bool:
    while group is not None:
        if group.uuid == bin_uuid:
            return True
        group = group.parentgroup
    return False


def records(kp: PyKeePass, match: Callable | None = None) -> list[EntryRecord]:
    rb = kp.recyclebin_group
    bin_uuid = rb.uuid if rb is not None else None
    out = []
    for e in kp.entries:
        if match is not None and not match(e):
            continue
        props = e.custom_properties or {}
        out.append(
            EntryRecord(
                title=e.title or "",
                group=_gpath(e.group),
                username=e.username or "",
                url=e.url or "",
                tags=list(e.tags or []),
                totp_style=_totp_style(e, props),
                custom_fields=sorted(props),
                attachments=len(e.attachments or []),
                notes_length=len(e.notes or ""),
                password_length=len(e.password or ""),
                created=_aware(e.ctime),
                modified=_aware(e.mtime),
                accessed=_aware(e.atime),
                expires=_aware(e.expiry_time) if e.expires else None,
                in_recycle_bin=bin_uuid is not None and _in_bin(e.group, bin_uuid),
            )
        )
    return sorted(out, key=lambda r: (r.group, r.title))


def detail(kp: PyKeePass, title: str, show_password: bool) -> EntryDetail | None:
    e = kp.find_entries(title=title, first=True)
    if e is None:
        return None
    return EntryDetail(
        title=e.title or "",
        group=_gpath(e.group),
        username=e.username or "",
        url=e.url or "",
        password=(e.password or "") if show_password else "********",
        notes=e.notes or "",
        tags=list(e.tags or []),
        custom_fields={k: str(v) for k, v in (e.custom_properties or {}).items()},
    )


def tree(kp: PyKeePass, with_entries: bool) -> GroupNode:
    def walk(g) -> GroupNode:
        return GroupNode(
            name=g.name or "/",
            entry_count=len(g.entries),
            entries=sorted(e.title or "" for e in g.entries) if with_entries else [],
            children=[walk(c) for c in sorted(g.subgroups, key=lambda x: x.name or "")],
        )

    return walk(kp.root_group)


def _age_bucket(modified: datetime | None, now: datetime) -> str:
    if modified is None:
        return "unknown"
    age = now - modified
    if age < timedelta(days=365):
        return "<1y"
    if age < timedelta(days=3 * 365):
        return "1-3y"
    if age < timedelta(days=5 * 365):
        return "3-5y"
    return ">5y"


def _len_bucket(n: int) -> str:
    if n == 0:
        return "empty"
    for limit, name in ((8, "<8"), (12, "8-11"), (16, "12-15"), (20, "16-19")):
        if n < limit:
            return name
    return "20+"


def inventory(kp: PyKeePass, path: Path) -> Inventory:
    now = datetime.now(timezone.utc)
    recs = records(kp)
    raw = list(kp.entries)  # same filter, for password-based metrics only

    # password metrics: values stay in memory, only counts leave
    pw_counts = Counter(e.password for e in raw if e.password)
    reused = [n for n in pw_counts.values() if n > 1]
    pw_eq_user = sum(1 for e in raw if e.password and e.password == e.username)

    title_counts = Counter(r.title for r in recs if r.title)
    uu_counts = Counter((r.url, r.username) for r in recs if r.url and r.username)

    custom = Counter(f for r in recs for f in r.custom_fields)
    tags = Counter(t for r in recs for t in r.tags)
    totp = Counter(r.totp_style for r in recs if r.totp_style)

    expiring = [r.expires for r in recs if r.expires]
    expiry = ExpiryStats(
        with_expiry=len(expiring),
        expired=sum(1 for d in expiring if d < now),
        due_30d=sum(1 for d in expiring if now <= d < now + timedelta(days=30)),
        due_90d=sum(1 for d in expiring if now <= d < now + timedelta(days=90)),
    )

    fields = FieldStats(
        missing_username=sum(1 for r in recs if not r.username),
        missing_url=sum(1 for r in recs if not r.url),
        missing_password=sum(1 for r in recs if r.password_length == 0),
        http_urls=sum(1 for r in recs if r.url.lower().startswith("http://")),
        with_notes=sum(1 for r in recs if r.notes_length),
        with_attachments=sum(1 for r in recs if r.attachments),
        attachment_count=sum(r.attachments for r in recs),
        custom_field_names=dict(custom),
    )

    never_modified = sum(
        1 for r in recs if r.created and r.modified and abs((r.modified - r.created).total_seconds()) < 2
    )

    groups = list(kp.groups)
    names = Counter(g.name for g in groups if g.name and g.uuid != kp.root_group.uuid)
    structure = StructureStats(
        max_depth=max((len(g.path) if isinstance(g.path, (list, tuple)) else 0 for g in groups), default=0),
        empty_groups=sum(1 for g in groups if not g.entries and not g.subgroups),
        groups_with_slash_in_name=sorted(g.name for g in groups if g.name and "/" in g.name),
        repeated_group_names={n: c for n, c in names.items() if c > 1},
    )

    meta = DbMeta(
        path=str(path),
        size_bytes=os.path.getsize(path),
        version=".".join(map(str, getattr(kp, "version", ()) or ())) or "?",
        cipher=str(getattr(kp, "encryption_algorithm", "?")),
        kdf=str(getattr(kp, "kdf_algorithm", "?")),
    )

    return Inventory(
        meta=meta,
        entries=len(recs),
        groups=len(groups),
        recycle_bin_entries=sum(1 for r in recs if r.in_recycle_bin),
        modified_age=dict(Counter(_age_bucket(r.modified, now) for r in recs)),
        never_modified=never_modified,
        expiry=expiry,
        fields=fields,
        totp=dict(totp),
        tags=dict(tags),
        untagged_entries=sum(1 for r in recs if not r.tags),
        duplicates=DuplicateStats(
            repeated_titles=sum(1 for n in title_counts.values() if n > 1),
            repeated_url_username=sum(1 for n in uu_counts.values() if n > 1),
            password_reuse_clusters=len(reused),
            password_reuse_entries=sum(reused),
        ),
        quality=QualityStats(
            password_length=dict(Counter(_len_bucket(r.password_length) for r in recs)),
            password_equals_username=pw_eq_user,
        ),
        structure=structure,
    )
