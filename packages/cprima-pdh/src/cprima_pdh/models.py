"""KDBX-specific data model.

Entry/inventory models carry no secret values (password, OTP secret, notes
text): only derived facts such as lengths and counts. EntryDetail is the one
exception and only holds a password when explicitly requested.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Finding levels, borrowed 1:1 from log levels: ERROR = structure is broken, WARN = hygiene / policy,
# INFO = a hint. The exit code of `validate` depends on ERROR only (see `--fail-on`).
Level = Literal["INFO", "WARN", "ERROR"]
LEVEL_ORDER: dict[str, int] = {"INFO": 1, "WARN": 2, "ERROR": 3}


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class DbMeta(Frozen):
    path: str
    size_bytes: int
    version: str
    cipher: str
    kdf: str


class EntryRecord(Frozen):
    title: str
    group: str
    username: str
    url: str
    tags: list[str] = Field(default_factory=list)
    totp_style: str | None = None  # how its one-time password is stored: "otp" or an OTP plugin style (see the backend)
    custom_fields: list[str] = Field(default_factory=list)
    attachments: int = 0
    notes_length: int = 0
    password_length: int = 0
    created: datetime | None = None
    modified: datetime | None = None
    accessed: datetime | None = None
    expires: datetime | None = None  # set only if expiry is enabled
    in_recycle_bin: bool = False


class EntryList(Frozen):
    entries: list[EntryRecord]


class EntryDetail(Frozen):
    title: str
    group: str
    username: str
    url: str
    password: str  # masked unless --show-password
    notes: str
    tags: list[str] = Field(default_factory=list)
    custom_fields: dict[str, str] = Field(default_factory=dict)


class TagCounts(Frozen):
    tags: dict[str, int]
    untagged_entries: int


class TreeEntry(Frozen):
    title: str
    schemas: list[str] = Field(default_factory=list)  # the record types its `_schema` names
    by_fields: list[str] = Field(default_factory=list)  # further types that follow from its fields (match rules)


class GroupNode(Frozen):
    """A group seen through the method: level (owner, area), totals, record types, and what looks out of place."""
    name: str
    kind: Literal["root", "owner", "area", "group", "recycle-bin"] = "group"
    total: int = 0  # every entry below this group (a recycle bin: what it holds, not part of any total)
    typed: int = 0  # of those, entries with a valid `_schema`
    entry_count: int = 0  # entries directly in this group
    note: str = ""  # what the method would not expect here
    collapsed: bool = False  # something below is not shown (--depth)
    entries: list[TreeEntry] = Field(default_factory=list)  # only with --entries
    children: list[GroupNode] = Field(default_factory=list)


GroupNode.model_rebuild()


class ExpiryStats(Frozen):
    with_expiry: int
    expired: int
    due_30d: int
    due_90d: int


class FieldStats(Frozen):
    missing_username: int
    missing_url: int
    missing_password: int
    http_urls: int
    with_notes: int
    with_attachments: int
    attachment_count: int
    attachment_bytes: int = 0  # total size of the attached files; never their content
    custom_field_names: dict[str, int]


class DuplicateStats(Frozen):
    repeated_titles: int  # distinct titles used by >1 entry
    repeated_url_username: int  # distinct (url, username) pairs used by >1 entry
    password_reuse_clusters: int
    password_reuse_entries: int


class QualityStats(Frozen):
    password_length: dict[str, int]
    password_equals_username: int


class StructureStats(Frozen):
    max_depth: int
    empty_groups: int
    groups_with_slash_in_name: list[str]
    repeated_group_names: dict[str, int]


class Change(Frozen):
    entry: str
    field: str
    old: str  # secrets are shown as "(hidden)"
    new: str
    action: str  # "set" | "unchanged" | "skipped: field not empty (use --overwrite)"
    applied: bool = False


class OrgChange(Frozen):
    kind: str  # "new-group" | "move"
    target: str  # the new group's path, or the entry being moved
    dest: str  # parent group (new-group) or destination group (move)
    applied: bool = False


class HistorySnapshot(Frozen):
    index: int  # 0 is the oldest
    modified: datetime | None = None
    changed: list[str] = Field(default_factory=list)  # names of what differs from the next newer state; never values


class HistoryReport(Frozen):
    entry: str
    snapshots: list[HistorySnapshot]


class FillItem(Frozen):
    entry: str  # group/title
    field: str  # the secret field's name, never a value
    how: str  # to type | to generate (dry run); typed | generated | skipped (applied)


class FillReport(Frozen):
    target: str  # the entry or group asked for
    entries: int  # entries that lack a secret field
    fields: int  # secret fields still empty
    generated: int = 0
    typed: int = 0
    skipped: int = 0
    items: list[FillItem] = Field(default_factory=list)
    applied: bool = False


class HistoryPrune(Frozen):
    keep: int
    entries: int  # entries that lose snapshots
    removed: int  # snapshots removed (or to be removed)
    applied: bool = False


class AttachmentItem(Frozen):
    name: str
    size: int  # bytes of the content; the content itself is never reported


class AttachmentsReport(Frozen):
    entry: str
    attachments: list[AttachmentItem]


class DbSettings(Frozen):
    name: str
    description: str
    history_max_items: int  # -1 = unlimited
    history_max_size: int  # bytes, -1 = unlimited
    recycle_bin: bool
    changed: list[str] = Field(default_factory=list)  # settings that differ from what was asked for
    applied: bool = False


class DbKdf(Frozen):
    algorithm: str
    iterations: int | None = None
    memory_kib: int | None = None
    parallelism: int | None = None
    applied: bool = False


class DbBin(Frozen):
    entries: int  # entries in the recycle bin (to be) deleted for good
    groups: int
    applied: bool = False


class FileWritten(Frozen):
    """The result of an export: which file was written and how much; never a value."""
    kind: str  # attachment | csv | kdbx
    path: str
    entries: int
    bytes: int


class ImportReport(Frozen):
    kind: str  # csv | xlsx | vault
    source: str
    entries: int
    groups: int  # groups that would be (or were) created
    columns: list[str] = Field(default_factory=list)  # spreadsheet columns that become custom fields
    secrets_to_fill: int = 0  # secret fields (by the taxonomy) of the imported entries that are still empty: none came with the file
    applied: bool = False


class MergeReport(Frozen):
    source: str
    added: int  # entries only the other copy has (and the ones a person asked to be brought back)
    updated: int  # entries whose newer state came from the other copy
    moved: int
    trashed: int  # moved to the recycle bin because the other copy has them there
    unchanged: int
    skipped: int  # in the other copy's bin or deleted here: not brought back
    entries: list[str] = Field(default_factory=list)  # paths of the entries that change
    applied: bool = False
    deleted: int = 0  # entries removed for good because the other copy's record says they were deleted
    groups_deleted: int = 0
    records_copied: int = 0  # deletion records the other copy had and this vault lacked
    changes: list["MergeChange"] = Field(default_factory=list)  # what is done by itself
    conflicts: list["MergeConflict"] = Field(default_factory=list)  # what a person decides
    unresolved: int = 0  # conflicts without an answer: while there are any, nothing is written


MergeChangeKind = Literal["add", "update", "move", "trash", "delete", "delete-group"]
MergeConflictKind = Literal["both-modified", "deleted-there-modified-here", "deleted-here-modified-there"]
MergeChoice = Literal["mine", "theirs", "keep", "delete"]


class MergeChange(Frozen):
    """One thing a merge does by itself, because nothing is lost by it."""
    kind: MergeChangeKind
    id: str  # the entry's (or, for delete-group, the group's) id
    path: str


class MergeConflict(Frozen):
    """Where one copy's change would be dropped by the other's: a person decides. Names, ids, paths and times only, never a value."""
    id: str
    path: str
    kind: MergeConflictKind
    fields: list[str] = Field(default_factory=list)  # both-modified: the names of the fields that differ
    mine_modified: datetime | None = None  # last modification in this vault
    theirs_modified: datetime | None = None  # last modification in the other copy
    deleted_at: datetime | None = None  # when the deletion was recorded, for the deletion conflicts
    choices: list[MergeChoice] = Field(default_factory=list)  # what may be answered
    reason: str = ""


class MergeSituation(Frozen):
    """What merging another copy into this vault would do, as data. Nothing is written and nothing is asked: a renderer shows it,
    a person (or a program) answers the conflicts, `merge_apply` writes."""
    source: str
    clean: list[MergeChange] = Field(default_factory=list)
    conflicts: list[MergeConflict] = Field(default_factory=list)
    unchanged: int = 0
    skipped: int = 0  # not brought back: in the other copy's bin, or deleted here and not changed since
    groups_kept: int = 0  # a deleted group that still holds something stays
    records_to_copy: int = 0  # deletion records this vault lacks (or has with a later time)


MergeReport.model_rebuild()  # (it names MergeChange and MergeConflict, which come after it)


class Generated(Frozen):
    """A generated password or passphrase. It is printed on purpose: the owner asked for it."""
    kind: str  # password | passphrase
    value: str
    entropy_bits: float


class OtpCode(Frozen):
    code: str
    period: int
    valid_for: int  # seconds until it changes; 0 for a counter-based code


class OnlineFinding(Frozen):
    """What every online result carries once the profile has judged it (see `online.judge`)."""
    rule: str = ""
    level: Level = "WARN"
    action: str = ""
    note: str = ""


class KnownPassword(OnlineFinding):
    entry: str
    count: int  # how often the password appears in known leaks


class KnownPasswordsReport(Frozen):
    source: str  # online | file
    checked: int  # entries with a password
    exposed: list[KnownPassword]  # entry paths and counts; never a password or a hash


class BreachHit(OnlineFinding):
    entry: str
    breach: str
    domain: str
    breach_date: str
    data_classes: list[str]
    changed_since: bool  # the entry was last changed on or after the breach date


class AccountHit(OnlineFinding):
    entry: str
    breaches: list[str]


class BreachReport(Frozen):
    catalogue: int  # breaches in the public catalogue
    hits: list[BreachHit]
    accounts: list[AccountHit] = Field(default_factory=list)


class FixAction(Frozen):
    entry: str
    key: str
    action: str  # "rename" | "protect" | "unprotect" | "skipped: <reason>"
    new_key: str | None = None

    def __str__(self) -> str:
        arrow = f" -> {self.new_key}" if self.new_key else ""
        return f"{self.action:10} {self.entry}: {self.key}{arrow}"


class FixPlan(Frozen):
    applied: bool
    entries_touched: int
    counts: dict[str, int]
    actions: list[FixAction]


class FieldUsage(Frozen):
    name: str
    entries: int
    protected: int


class GroupProfile(Frozen):
    name: str  # leaf group name; repeated names across branches are merged
    paths: list[str]
    entries: int
    with_username: int
    with_url: int
    with_notes: int
    with_expiry: int
    with_totp: int
    https_urls: int
    custom_fields: list[FieldUsage]

    def __str__(self) -> str:
        head = (
            f"{self.name}  entries={self.entries} user={self.with_username} url={self.with_url} "
            f"https={self.https_urls} notes={self.with_notes} expiry={self.with_expiry} totp={self.with_totp}"
        )
        paths = f"\n      in: {', '.join(self.paths)}"
        fields = "".join(
            f"\n      {f.name}: {f.entries}/{self.entries}" + (f" (protected {f.protected})" if f.protected else "")
            for f in self.custom_fields
        )
        return head + paths + fields


class InferReport(Frozen):
    profiles: list[GroupProfile]


class CompiledRule(Frozen):
    id: str
    level: Level
    message: str
    xpath: str  # evaluated relative to an <Entry>; true / non-empty result = violation

    def __str__(self) -> str:
        return f"{self.level:5} {self.id:28} {self.xpath}"


class Link(Frozen):
    source: str  # group/title of the entry that holds the link
    field: str
    target: str | None  # group/title of the target; None when it does not resolve
    status: str  # ok | dangling | invalid | self | wrong-schema | target-unclassified

    def __str__(self) -> str:
        return f"{self.status:20} {self.source} --[{self.field}]--> {self.target or '?'}"


class LinksReport(Frozen):
    links: list[Link]
    per_target: dict[str, int]  # how many links point at each resolved target


class TaxonomyDoc(Frozen):
    markdown: str


class UnclassifiedReport(Frozen):
    total: int  # live entries without a valid `_schema`
    per_group: dict[str, int]
    entries: list[str] = Field(default_factory=list)  # `group/title`, only with --entries


class Issue(Frozen):
    """One way an entry does not conform, with what an agent can do about it. Never carries a value."""
    schema_name: str = Field(alias="schema")
    rule: str
    level: Level
    fields: list[str] = Field(default_factory=list)
    message: str
    action: str  # supply-value | rename-field | protect-field | unprotect-field | decide-field | review-url | ...
    automatable: bool  # True: an agent may run `command` without asking the owner
    command: str | None = None  # a pdh command line; `<...>` marks what the owner has to supply
    note: str

    model_config = ConfigDict(frozen=True, populate_by_name=True)


class EntryConformance(Frozen):
    entry: str  # `group/path/title`
    username: str
    status: Literal["conform", "nonconform", "unclassified"]
    schemas: list[str]
    issues: list[Issue] = Field(default_factory=list)

    def __str__(self) -> str:
        head = f"{self.status:11} {self.entry}  [{', '.join(self.schemas) or '-'}]"
        lines = [f"{i.level:5} {i.rule} -> {i.action}{' (automatable)' if i.automatable else ''}"
                 + (f"\n        $ {i.command}" if i.command else "") for i in self.issues]
        return "\n    ".join([head, *lines])


class ConformanceReport(Frozen):
    conform: int  # counts cover every live entry, whatever the list below is filtered to
    nonconform: int
    unclassified: int
    entries: list[EntryConformance]


class BackendRow(Frozen):
    name: str
    ready: bool  # its dependencies are installed
    detail: str
    detection: str = ""  # how a file of this kind is recognised
    capabilities: list[str] = []  # what its vault can do


class BackendList(Frozen):
    backends: list[BackendRow]


class SessionState(Frozen):
    """The result of every `pdh session` command: what was done and where the session stands. Never a secret."""
    action: Literal["unlocked", "locked", "no-session", "status"]
    unlocked: bool
    seconds_left: int = 0
    minutes: int = 0  # the lifetime requested by `unlock`


class ProfileInfo(Frozen):
    name: str  # the full name, e.g. pdh-default
    taxonomy: str
    version: str
    description: str = ""


class ProfileList(Frozen):
    profiles: list[ProfileInfo]


CheckStatus = Literal["ok", "warn", "fail", "skip"]


Section = Literal["setup", "file", "method"]


class DoctorCheck(Frozen):
    """One line of `pdh doctor`: what was looked at, how it stands, and what to do about it."""
    section: Section
    name: str
    status: CheckStatus
    detail: str
    hint: str = ""

    def __str__(self) -> str:
        line = f"[{self.status:4}] {self.name:12} {self.detail}"
        return line + (f"\n{'':20}-> {self.hint}" if self.hint else "")


class DoctorReport(Frozen):
    checks: list[DoctorCheck]

    @property
    def failed(self) -> bool:
        return any(c.status == "fail" for c in self.checks)


class SchemaView(Frozen):
    description: str
    facets: list[str]
    rules: list[CompiledRule]


class TypedEntry(Frozen):
    schema_name: str = Field(alias="schema")
    entry: str
    fields: dict[str, str]  # protected values appear as "(protected)"

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    def __str__(self) -> str:
        vals = "; ".join(f"{k}={v.replace(chr(10), ' / ')}" for k, v in self.fields.items())
        return f"{self.schema_name}: {self.entry}  {vals}"


class ReadReport(Frozen):
    entries: list[TypedEntry]
    unclassified_entries: int


class SchemaRules(Frozen):
    schemas: dict[str, SchemaView]
    vocabulary: dict[str, str] = Field(default_factory=dict)  # global field terms


class RuleFinding(Frozen):
    schema_name: str = Field(alias="schema")
    entry: str
    rule: str
    level: Level
    message: str
    fields: list[str] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    def __str__(self) -> str:
        extra = f" ({', '.join(self.fields)})" if self.fields else ""
        return f"{self.level:5} {self.schema_name}: {self.entry}: {self.message}{extra}"


class SchemaStats(Frozen):
    entries: int
    conforming: int
    with_findings: int


class RuleCount(Frozen):
    schema_name: str
    rule: str
    level: Level
    entries: int

    def __str__(self) -> str:
        return f"{self.level:5} {self.entries:>5}  {self.schema_name}: {self.rule}"


class ValidationSummary(Frozen):
    schemas: dict[str, SchemaStats]
    unclassified_entries: int
    rules: list[RuleCount]  # most frequent first


class ValidationReport(Frozen):
    schemas: dict[str, SchemaStats]
    unclassified_entries: int
    findings: list[RuleFinding]


class HistoryStats(Frozen):
    snapshots: int = 0  # older versions of entries kept in their History
    entries_with_history: int = 0
    bytes: int = 0  # size of those versions in the file (old values live there)


class Inventory(Frozen):
    meta: DbMeta
    entries: int
    groups: int
    recycle_bin_entries: int
    modified_age: dict[str, int]
    never_modified: int
    expiry: ExpiryStats
    fields: FieldStats
    totp: dict[str, int]
    tags: dict[str, int]
    untagged_entries: int
    duplicates: DuplicateStats
    quality: QualityStats
    structure: StructureStats
    history: HistoryStats = HistoryStats()
