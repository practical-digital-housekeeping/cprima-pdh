# Merging two copies of a KDBX vault: direction and rules

Knowledge-base entry, 2026-10-05. Licensed under CC-BY-4.0.

Two copies of one vault drift apart (sync conflicts, a phone and a laptop). A merge brings them together. This entry says which
copy changes, how KeePassXC decides, and what pdh does differently. Marks: **seen** = read in the KeePassXC source here
(`D:\github.com\keepassxreboot\keepassxc`, `src/core/Merger.cpp`) or shown by a pdh run; **mine** = how pdh behaves.

## Direction

A merge is `merge(target, source)`. Only the target changes and is saved; the source is only read. **Seen:** KeePassXC's
`keepassxc-cli merge` builds `Merger merger(db2, database)`, `db2` being the source. **Mine:** `pdh io merge OTHER` runs on the
vault given with `--db`, which is the target; the other copy is never written.

The direction matters for: which copy keeps its state on equal times (the target), which copy can lose entries (the target), and
which file's own settings stay (master key, key derivation, `Meta/Generator`).

## How KeePassXC decides (seen)

- Same entry in both: the newer `lastModificationTime` wins and the histories are merged; equal times keep the target
  (`resolveEntryConflict_MergeHistories`).
- The mode is not stored in the file. The default, also for `keepassxc-cli merge`, is `KeepNewer`: nothing is deleted, an entry the
  target lacks is copied in, deletion records are kept but not applied.
- Only `Synchronize` mode applies deletions (`mergeDeletions`): both lists are combined with the earliest time per id; an entry in
  the target is removed unless it was modified after the deletion; a group is removed unless it is newer or still holds something.

## What a deletion needs

A deleted entry must leave a `DeletedObject` (id and time) in `Root/DeletedObjects`, otherwise a merge cannot tell "deleted" from
"never arrived". See `kdbx-xml-structure.md`. pdh writes one for every permanent delete (`purge`, `purge_group`, emptying the
bin); moving to the bin is only a move and writes none.

## What pdh does (mine)

The way git does: what loses nothing is done by itself; where one copy's change would be dropped by the other's, it is a
**conflict** and a person decides. Nothing is written while a conflict is open, and the exit code is 1.

| Case | Result |
|---|---|
| Entry only in the other copy; not in its bin; not deleted here | added |
| Both copies, same state | nothing |
| Both copies, one copy's current state is among the other's earlier states (the history) | the newer one is taken without a question |
| Both copies changed it and neither includes the other | conflict `both-modified`: `mine` or `theirs` |
| Moves, entries in the other copy's bin | followed (nothing is lost) |
| The other copy has a deletion record, this entry unchanged since | removed for good |
| The other copy has a deletion record, this entry changed after it | conflict `deleted-there-modified-here`: `keep` or `delete` |
| This vault deleted it, the other copy did not change it since | stays deleted |
| This vault deleted it, the other copy changed it after | conflict `deleted-here-modified-there`: `keep` or `delete` |
| Deleted group, empty after its entries went | removed |

Order comes from the entries' own **history** (as git uses a common ancestor), not from clocks. A clock is used for one question
only: was an entry changed after it was deleted. Without history (a client that keeps none) the safe answer is a conflict.

The situation is data (`MergeSituation`, built by `merge.merge_situation`): changes, conflicts with entry id, path, the *names*
of the differing fields and the times, never a value. The text on a terminal is only a renderer of it. Answers come in as data:
`--resolve ID=mine|theirs` (or `keep|delete`), or an explicit `--prefer mine|theirs`; the default asks nothing and decides
nothing. After a resolved merge, merging the result back into the other copy ends the conflict there too, and both copies then hold
the same entries and the same deletion records.

## Not covered

Group modification times (a group is judged by being empty), a "keep both" copy of a conflicting entry, merging more than two
copies at once, and any interactive prompt (a front end could produce the same answers).
