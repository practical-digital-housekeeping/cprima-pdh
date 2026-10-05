"""`pdh doctor`: one overview in three sections.

- **setup**: is pdh ready (version, backend, taxonomy, session)?
- **file**: is the .kdbx healthy (format and key derivation from the header, which needs no password; lock file and
  sync conflicts; with an unlocked session: size drivers such as history and attachments, recycle bin, expiry, TOTP)?
- **method**: how far along is the vault on the axes of the method (owners, areas, record types, vocabulary,
  conformance, hygiene, relations)? This shows progress; only rule ERRORs and broken links turn a line to `warn`.

Read-only and never prompts: contents are only read when a session is already unlocked for this vault.
No value of any field is ever part of the report: only names, counts and sizes.
"""
from __future__ import annotations

import platform
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from . import __version__, backends, session
from cprima_pdh_kdbxkit.kdbx_format import OTP_PREFIXES
from .models import DoctorCheck, DoctorReport
from .policy import WRITE_POLICY

_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")  # KeePass 2.x file signature
_CIPHERS = {"31c1f2e6bf714350be5805216afc5aff": "AES-256", "d6038a2b8b6f4cb5a524339a31dbb59a": "ChaCha20",
            "ad68f29f576f4bb9a36ad47af965346c": "Twofish"}
_KDFS = {"ef636ddf8c29444b91f7a9a403e30a0c": "Argon2d", "9e298b1956db4773b23dfc3ec6f0a1e6": "Argon2id",
         "c9d9f39a628a4460bf740d08c18a4fea": "AES-KDF", "7c02bb8279a74ac0927d114a00648238": "AES-KDF"}
# below these, the key derivation is weak (KeePass defaults: AES-KDF 60,000 rounds; Argon2 64 MiB)
MIN_AES_ROUNDS = 60_000
MIN_ARGON2_MEMORY = 16 * 1024 * 1024
MIN_ARGON2_ITERATIONS = 2


# --- the file header (no password) ---------------------------------------------------------------

def kdbx_header(path: Path) -> dict:
    """Format, cipher, compression and key derivation from the KDBX header; nothing is decrypted.

    Raises ValueError for a file that is not KDBX. KDBX 3.x header fields have 2-byte lengths, 4.x 4-byte ones.
    """
    with open(path, "rb") as f:
        b = f.read(64 * 1024)  # the header is small; the encrypted payload follows it
    if len(b) < 12 or b[:8] != _SIGNATURE:
        raise ValueError("not a KDBX file")
    minor, major = int.from_bytes(b[8:10], "little"), int.from_bytes(b[10:12], "little")
    size_len = 4 if major >= 4 else 2
    out: dict = {"format": f"KDBX {major}.{minor}"}
    i = 12
    while i < len(b):
        t, n = b[i], int.from_bytes(b[i + 1:i + 1 + size_len], "little")
        v = b[i + 1 + size_len:i + 1 + size_len + n]
        i += 1 + size_len + n
        if t == 0:
            break
        if t == 2:
            out["cipher"] = _CIPHERS.get(v.hex(), "unknown")
        elif t == 3:
            out["compression"] = "gzip" if int.from_bytes(v, "little") == 1 else "none"
        elif t == 6:  # KDBX 3.x: AES-KDF transform rounds
            out["kdf"], out["rounds"] = "AES-KDF", int.from_bytes(v, "little")
        elif t == 11:  # KDBX 4.x: variant dictionary of KDF parameters
            out.update(_kdf_params(v))
    return out


def _kdf_params(v: bytes) -> dict:
    out, j = {}, 2  # skip the dictionary version
    while j < len(v) and v[j] != 0:
        kl = int.from_bytes(v[j + 1:j + 5], "little")
        key = v[j + 5:j + 5 + kl].decode("utf-8", "replace")
        j += 5 + kl
        vl = int.from_bytes(v[j:j + 4], "little")
        val = v[j + 4:j + 4 + vl]
        j += 4 + vl
        if key == "$UUID":
            out["kdf"] = _KDFS.get(val.hex(), "unknown")
        elif key in ("I", "M", "P", "R"):
            out[{"I": "iterations", "M": "memory", "P": "threads", "R": "rounds"}[key]] = int.from_bytes(val, "little")
    return out


def _kdf_text(h: dict) -> tuple[str, bool]:
    """Readable key derivation and whether it is weak."""
    if h.get("kdf") == "AES-KDF":
        rounds = h.get("rounds", 0)
        return f"AES-KDF {rounds:,} rounds", rounds < MIN_AES_ROUNDS
    if str(h.get("kdf", "")).startswith("Argon2"):
        mem, it, th = h.get("memory", 0), h.get("iterations", 0), h.get("threads", 0)
        return (f"{h['kdf']} {mem // 1_048_576} MiB, {it} iterations, {th} threads",
                mem < MIN_ARGON2_MEMORY or it < MIN_ARGON2_ITERATIONS)
    return "unknown key derivation", True


def _size(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB"
    return f"{n / 1024:.0f} KB" if n >= 1024 else f"{n} bytes"


# --- the report ----------------------------------------------------------------------------------

class _Report:
    def __init__(self) -> None:
        self.checks: list[DoctorCheck] = []

    def add(self, section: str, name: str, status: str, detail: str, hint: str = "") -> None:
        self.checks.append(DoctorCheck(section=section, name=name, status=status, detail=detail, hint=hint))

    def done(self) -> DoctorReport:
        return DoctorReport(checks=self.checks)


def diagnose(db: Path | None, taxonomy: Callable[[], object], taxonomy_source: str,
             open_unlocked: Callable[[Path], object | None], vault_source: str = "--db",
             taxonomy_origin: str = "", backend_choices: tuple = (), unlock_channel: str = "") -> DoctorReport:
    """`taxonomy()` loads the taxonomy (raises on error); `open_unlocked(db)` returns the opened vault only when a
    session is unlocked for it, else None. It must never prompt."""
    r = _Report()

    # --- setup
    r.add("setup", "pdh", "ok", f"{__version__} (cprima-pdh), Python {platform.python_version()}")
    try:
        chosen = backends.select(db, backend_choices) if db is not None and db.is_file() else backends.Selection(
            backends.BUILT_IN_DEFAULT, "built-in default (no vault file)")
        kind = chosen.name
        backends.load(kind)
        r.add("setup", "backend", "ok", f"{kind} ready (from {chosen.source})")
        kdbx_ready = True
    except backends.BackendMissing as exc:
        kind = "the selected"
        r.add("setup", "backend", "fail", str(exc).split("; install it with: ")[0], str(exc).split("install it with: ")[-1]
              if "install it with: " in str(exc) else "choose one with --backend NAME")
        kdbx_ready = False
    sset = None
    try:
        sset = taxonomy()
        label = f"{taxonomy_source} v{sset.profile.version}" if sset.profile else taxonomy_source
        label += f" ({taxonomy_origin})" if taxonomy_origin else ""
        proposed = (f" ({len(sset.proposed_schemas)} + {len(sset.proposed_fields)} proposed)"
                    if sset.proposed_schemas or sset.proposed_fields else "")
        r.add("setup", "taxonomy", "ok", f"{label}: {len(sset.schemas)} record types, {len(sset.fields)} terms{proposed}")
    except Exception as exc:  # SchemaError and file problems alike
        r.add("setup", "taxonomy", "fail", f"{taxonomy_source}: {exc}", "fix the taxonomy file or drop --schemas")

    if db is None:  # not an error: doctor still reports the setup
        r.add("setup", "vault", "warn", "no vault given",
              "pass --db or --vault, set KDBX_FILE, or configure one in pdh.toml / ~/.config/cprima-pdh/config.toml")
        r.add("file", "vault", "skip", "no vault given")
        r.add("method", "progress", "skip", "no vault given")
        return r.done()
    r.add("setup", "vault", "ok", f"from {vault_source}")
    from .source import sidecar

    side = sidecar(db)
    left = session.seconds_left()
    unlocked_here = bool(unlock_channel) or side is not None or (left > 0 and session.load_session(db) is not None)
    if kind == "sops":
        unlocked_here = True  # no password and no session: an age identity opens it, or nothing does
        r.add("setup", "session", "ok", "not needed: an age identity opens it (--key, SOPS_AGE_KEY_FILE or the default key file)")
    elif unlock_channel:
        r.add("setup", "session", "ok", f"not needed: the passphrase comes from {unlock_channel}")
    elif side is not None:
        r.add("setup", "session", "ok", f"not needed: password from sidecar {side.name} (test fixture)")
    elif not left:
        r.add("setup", "session", "warn", "locked", "pdh session unlock (then contents and method are shown too)")
    elif not unlocked_here:
        r.add("setup", "session", "warn", f"unlocked for another vault ({left // 60} min left)",
              "pdh session unlock for this one")
    else:
        r.add("setup", "session", "ok", f"unlocked, {left // 60} min left")

    # --- file: header and side files
    if not db.is_file():
        r.add("file", "vault", "fail", f"{db} does not exist", "check --db / KDBX_FILE")
        return r.done()
    st = db.stat()
    changed = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
    if kind == "sops":
        r.add("file", "vault", "ok", f"{db} ({_size(st.st_size)}, changed {changed})")
        r.add("file", "in use", "ok", "a plain file: no lock; concurrent edits conflict in git")
        return _sops_rest(r, db, sset, open_unlocked)
    try:
        h = kdbx_header(db)
    except (ValueError, OSError) as exc:
        r.add("file", "vault", "fail", f"{db}: {exc}")
        return r.done()
    r.add("file", "vault", "ok", f"{db} ({_size(st.st_size)}, changed {changed})")
    kdf, weak = _kdf_text(h)
    r.add("file", "format", "warn" if weak else "ok",
          f"{h['format']} · {h.get('cipher', 'unknown cipher')} · {kdf} · compression {h.get('compression', '?')}",
          "raise the key derivation cost in the client (Database Security)" if weak else "")
    locks = WRITE_POLICY.lock_files(db)
    conflicts = sorted(db.parent.glob(f"{db.stem}.sync-conflict-*{db.suffix}"))
    if locks:
        r.add("file", "in use", "warn", f"lock file {locks[0].name}: another program has the vault open",
              "close the vault in that program before `pdh edit ... --apply`")
    if conflicts:
        r.add("file", "in use", "warn", f"{len(conflicts)} sync-conflict cop{'y' if len(conflicts) == 1 else 'ies'}",
              f"merge or delete them in the client, e.g. {conflicts[0].name}")
    if not locks and not conflicts:
        r.add("file", "in use", "ok", "no lock file, no sync conflict (a program that makes no lock file, KeePassXC for one, is not seen)")

    if not (unlocked_here and kdbx_ready):
        r.add("file", "contents", "skip", "needs an unlocked session")
        r.add("method", "progress", "skip", "needs an unlocked session")
        return r.done()
    try:
        kp = open_unlocked(db)
    except Exception as exc:
        r.add("file", "contents", "fail", f"could not open: {exc}", "pdh session unlock again")
        return r.done()
    if kp is None:
        r.add("file", "contents", "skip", "session not usable for this vault")
        return r.done()

    from cprima_pdh_vault.vault import as_vault

    vault = as_vault(kp)
    live = _file_contents(r, vault)
    if sset is None:
        r.add("method", "progress", "skip", "needs a valid taxonomy")
    else:
        _method(r, vault, sset, live)
    return r.done()


def _sops_rest(r: _Report, db: Path, sset, open_unlocked) -> DoctorReport:
    """The file and method sections of a sops file: the format from the backend, then the same checks as for any vault."""
    try:
        vault = open_unlocked(db)
    except Exception as exc:  # no identity, not a recipient, a bad MAC: say which
        r.add("file", "format", "fail", f"could not open: {exc}", "pass --key FILE or set SOPS_AGE_KEY_FILE; the file may be altered")
        r.add("file", "contents", "skip", "needs the age identity")
        r.add("method", "progress", "skip", "needs the age identity")
        return r.done()
    info = vault.info()
    r.add("file", "format", "ok", f"{info.format} · {info.cipher} · age, {info.extra.get('recipients', '?')} recipient(s) · "
                                  f"MAC {info.extra.get('mac', '?')}")
    live = _file_contents(r, vault)
    unmapped = info.extra.get("unmapped values", "0")
    if unmapped != "0":
        r.add("file", "mapping", "warn", f"{unmapped} value(s) are not part of any entry (a scalar beside groups)",
              "sops files map as groups of entries: a mapping of scalars is an entry")
    if sset is None:
        r.add("method", "progress", "skip", "needs a valid taxonomy")
    else:
        _method(r, vault, sset, live)
    return r.done()


# --- file: contents ------------------------------------------------------------------------------

def _file_contents(r: _Report, vault) -> list:
    """The file's facts from the backend's snapshots; what a backend cannot hold (a bin, history, attachments) is not shown."""
    entries, groups = vault.entries(), vault.groups()
    caps = vault.capabilities
    live = [e for e in entries if not e.in_bin]
    shown = [g for g in groups if not g.is_root and not g.is_bin and not g.in_bin]
    held = Counter(e.group_id for e in entries)
    kids = Counter(g.parent_id for g in groups if g.parent_id)
    empty = sum(1 for g in shown if not held[g.id] and not kids[g.id])
    at_root = sum(1 for e in live if e.group_path == "/")
    generator = vault.info().generator or "unknown"
    r.add("file", "contents", "ok", f"{len(live)} entr{'y' if len(live) == 1 else 'ies'} in {len(shown)} "
                                    f"group{'' if len(shown) == 1 else 's'} ({empty} empty), "
                                    f"{at_root} at the root; written by {generator}")

    if "recycle_bin" in caps:
        if any(g.is_bin for g in groups):
            r.add("file", "recycle bin", "ok", f"on, {sum(1 for e in entries if e.in_bin)} entries")
        else:
            r.add("file", "recycle bin", "ok", "off")
    if "history" in caps:
        r.add("file", "history", "ok", f"{sum(e.history_count for e in live)} older versions, "
                                       f"{_size(sum(e.history_bytes for e in live))}")
    if "attachments" in caps:
        files = [a for e in entries for a in e.attachments]
        r.add("file", "attachments", "ok", f"{len(files)} files, {_size(sum(size for _n, size in files))}")

    if "expiry" in caps:
        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=30)
        expiring = [e for e in live if e.expires and e.expiry is not None]
        expired = sum(1 for e in expiring if e.expiry <= now)
        due = sum(1 for e in expiring if now < e.expiry <= soon)
        r.add("file", "expiry", "warn" if expired else "ok",
              f"{len(expiring)} with an expiry date: {expired} expired, {due} within 30 days",
              "renew or retire the expired records" if expired else "")
    totp = sum(1 for e in live if e.otp or any(k.startswith(OTP_PREFIXES) for k in e.fields))
    r.add("file", "totp", "ok", f"{totp} entries with TOTP")
    return live


# --- method --------------------------------------------------------------------------------------

def _pct(n: int, total: int) -> str:
    return f"{n} of {total} ({round(100 * n / total) if total else 0} %)"


def _method(r: _Report, vault, sset, live: list) -> None:
    from cprima_pdh_vault.memory import MemoryVault
    from .conform import conformance
    from .schema import lookup_term, validate, vocabulary_index
    from .validation import links_for, typing_of

    snap = MemoryVault(vault.entries(), vault.groups())  # one snapshot for all the checks below
    total = len(live)
    paths = [e.group_path for e in live]

    # owners: the top-level groups
    owners = Counter(p.split("/")[0] for p in paths if p != "/")
    r.add("method", "owners", "ok",
          f"{len(owners)}: " + ", ".join(f"{o} {n}" for o, n in owners.most_common()) if owners else "none")

    # areas: the second level, compared with the starter areas
    second = [p.split("/")[1] if p.count("/") >= 1 else None for p in paths]
    in_area = sum(1 for a in second if a in sset.areas)
    others = sorted({a for a in second if a and a not in sset.areas})
    r.add("method", "areas", "ok", f"{_pct(in_area, total)} in starter areas; {len(others)} other sub-groups")

    # record types
    per_schema: Counter[str] = Counter()
    unknown_names: set[str] = set()
    typed = field_only = 0
    for e in live:
        t = typing_of(e, sset)  # the binding field and/or the profile's field-based match rules
        typed += bool(t.names)
        field_only += bool(t.by_fields and not t.explicit)
        per_schema.update(t.names)
        unknown_names.update(t.unknown)
    top = ", ".join(f"{s} {n}" for s, n in per_schema.most_common(5))
    r.add("method", "record types", "warn" if unknown_names else "ok",
          f"{_pct(typed, total)} typed" + (f": {top}" if top else "") +
          (f"; {field_only} only by field rules" if field_only else "") +
          (f"; {len(unknown_names)} unknown schema names" if unknown_names else ""),
          "pdh inspect unclassified  (the seeding to-do list)" if typed < total else "")

    # vocabulary: distinct custom field names
    exact, matchers = vocabulary_index(sset.fields)
    names = {k for e in live for k in e.fields if k != sset.binding.field and not k.startswith(OTP_PREFIXES)}
    kinds = Counter()
    for k in names:
        hit = lookup_term(k, exact, matchers)
        kinds["term" if hit and hit[2] and hit[0] == k else "alias" if hit and hit[2] else
              "pattern" if hit else "unsupported"] += 1
    report = validate(snap, sset)
    unprotected = sum(1 for f in report.findings if f.rule.startswith("protected:"))
    r.add("method", "vocabulary", "warn" if kinds["unsupported"] or unprotected else "ok",
          f"{len(names)} field names: {kinds['term']} terms, {kinds['pattern']} caught by a name pattern, "
          f"{kinds['alias'] + kinds['unsupported']} not terms; {unprotected} unprotected secrets",
          "pdh check conform  (action decide-field / protect-field)" if kinds["unsupported"] or unprotected else "")

    # conformance and levels
    rep = conformance(snap, sset, status="nonconform")
    levels = Counter(f.level for f in report.findings)
    lv = ", ".join(f"{levels[x]} {x}" for x in ("ERROR", "WARN", "INFO") if levels[x]) or "no findings"
    r.add("method", "conformance", "warn" if levels["ERROR"] else "ok",
          f"{rep.conform} conform, {rep.nonconform} nonconform, {rep.unclassified} unclassified; {lv}",
          "pdh check  (or -f json for an agent)" if rep.nonconform else "")

    # hygiene: counts only, never values
    # a login is an entry with a user name or a URL; cards, contracts and memberships have no password by design
    no_password = sum(1 for e in live if (e.username or e.url) and not e.password)
    http = sum(1 for e in live if e.url.lower().startswith("http://"))
    dupes = sum(1 for n in Counter((e.group_path, e.title) for e in live).values() if n > 1)
    r.add("method", "hygiene", "ok", f"{no_password} login{'' if no_password == 1 else 's'} without a password, "
                                     f"{http} http:// URLs (valid; a hint), {dupes} duplicate titles in a group")

    # relations
    links = links_for(snap.entries(), sset).links
    broken = sum(1 for lk in links if lk.status in ("invalid", "dangling", "self"))
    r.add("method", "relations", "warn" if broken else "ok",
          f"{len(links)} link{'' if len(links) == 1 else 's'}, {broken} broken",
          "pdh inspect links" if broken else "")
