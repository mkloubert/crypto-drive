# crypto-drive – One directory id per directory (no ids from `.cd-dir` copies)

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: entries under a
  copy with another id are hidden, the directory works; `check` reports a
  copy with another id as error `foreign-dir-id`; no vaults from before the
  format hardening exist). Implemented 2026-11-08, tested in the Linux
  container only
- **Author:** Marcel Joachim Kloubert
- **Source:** review 2026-11-08 (`REPORT.md`), finding SEC-5; README
  "Threat model", gap "Moves between directories with a planted `.cd-dir`
  copy"

## 1. Problem

The name of an entry is encrypted with the id of its parent directory as
associated data (`docs/format.md` 6), so an entry moved to another
directory does not decrypt there. But `docs/format.md` 10 item 3 requires a
reader to try the ids of up to 15 `.cd-dir` conflict copies too
(`read_dir_ids`, `fs/dirstate.rs`). So someone who can change the vault can
move entries from directory A to B and put a copy of A's `.cd-dir` into B:
the entries show up in B without an error (a warning in the log once per
mount, finding `multiple-dir-ids` in `check`, a warning only).

Worse, `rotate-key` uses the same ids: it encrypts such a name again under
the canonical id of B, which makes the move permanent and invisible even
to `check`.

A copy with **another** id has no legitimate source in the hardened format
v1: the dir id is random at `mkdir` and never changes, and it is the entry
id inside the encrypted directory name, so two devices that create the same
directory make two different real directories (also for long names, whose
`.cd-cdl` hash covers the name with the id). A sync conflict copy of
`.cd-dir` at one real path always holds the same 16 bytes. The owner
confirmed that no vault from before the format hardening exists.

The extra ids also make every listing try each name with up to 16 ids
(review SEC-3).

## 2. Goals

1. Every reader uses only the canonical `.cd-dir` id of a directory to
   decrypt the names of its children: the drive, `check`, `rotate-key`,
   and `rotation_unfinished` / `verify_next_key` (used by `recover` and
   `rotate-key`).
2. Entries whose name decrypts only under another id are hidden like any
   foreign entry; the directory works as usual (owner decision 1).
3. The drive warns once per mount per directory when a `.cd-dir` copy with
   another id exists; a copy with the same id is silent.
4. `check` reports a copy with the same id as `multiple-dir-ids`
   (warning) and a copy with another id as the new `foreign-dir-id`
   (error); names under it show as `undecryptable-name` (owner decision 2).
5. `rotate-key` never adopts an entry under a foreign id.

Not a goal: detecting entries that were removed from A (deletion stays
undetected, README "Threat model").

## 3. Design

### 3.1 Reading the id

`read_dir_ids` becomes
`read_dir_id(handle, real, names) -> Result<DirIds>` with

```rust
pub(crate) struct DirIds {
    /// The id in `.cd-dir`.
    pub(crate) id: DirId,
    /// True if a `.cd-dir` copy (a regular file of 16 bytes) holds another id.
    pub(crate) foreign_copy: bool,
}
```

Copies are found as today (name starts with `.cd-dir`, not `.cd-dir` and
not `.cd-dir.tmp`, regular file of exactly 16 bytes). At most
`MAX_DIR_ID_COPIES` (16) copies are read, in name order, so thousands of
planted copies cost nothing; reading stops at the first foreign one.
`MAX_DIR_IDS` goes away.

### 3.2 Drive

- `DirState.dir_ids: Vec<DirId>` becomes `dir_id: DirId` and
  `foreign_copy: bool`. The root has the `vault_id` and no copies.
- `listing.rs`: `decrypt_name` tries only `state.dir_id` (every epoch, as
  today); `id_index` goes away from `Found` / `Decrypted`, and the sort of
  new normal entries in `build_listing` is by real name only.
- `warn_extra_ids` becomes `warn_foreign_copy`: once per mount per
  directory (the existing `warned_extra_ids` flag of `SharedDir`), when
  `foreign_copy` is set, at `warn`, with the real path only:
  `a .cd-dir copy in {real} holds another directory id; entries named under it are not shown. Run crypto-drive check (foreign-dir-id).`
  Test counter as today (`extra_id_warnings`, renamed
  `foreign_copy_warnings`).

### 3.3 `check`

- `check_dir` no longer adds ids. For each copy: the same id as the
  canonical one → `MultipleDirIds` (warning); another id →
  `ForeignDirId` (new, severity error); not 16 bytes → `ForeignEntry` as
  today.
- CLI text in `crates/crypto-drive/src/cmd/check.rs`: `foreign-dir-id`
  (exact test). `FindingKind` is not a core `Error` variant, so no errno
  mapping is needed.

### 3.4 `rotate-key` and vault walks

`rotate.rs` (`open_child`, `walk_dir`, `list`, `count_old`,
`is_hidden_data`) and `vault.rs` (`walk_tree`, `rotation_unfinished`,
`verify_next_key`) take one `DirId` instead of a slice.

### 3.5 Limits

- A planted **long** entry (`.cd-cdl` with `.cd-content` or `.cd-dir`)
  under a foreign id counts as hidden data for `rotate-key`, which then
  stops with an error that names its real path, instead of adopting it.
  The same happens today with any planted `.cd-cdl` junk; the user removes
  the named entry.
- `rotate-key` does not finish while any directory holds a `.cd-dir` copy
  with another id (`RotationNotFinished.foreign_copies` names them): the
  entries named under it would be lost with the old key (added after the
  final review; long entries are also counted as hidden data).
- A planted short name under a foreign id makes `rotation_unfinished`
  true, as any planted name that does not decrypt does today.

## 4. Docs

- `docs/format.md` 6.1: drop the sentences that extra copies stay
  readable for children and that a move with a planted copy is not
  detected; the canonical `.cd-dir` is the only id.
- `docs/format.md` 10 item 3: "More than one `.cd-dir`: a control file
  whose name starts with `.cd-dir` and that is 16 bytes long (except
  `.cd-dir.tmp`) is a conflict copy. A sync client can only make copies
  with the same id. A reader MUST use only the canonical `.cd-dir` to
  decrypt names; it MUST NOT use the id of a copy. A checker SHOULD report
  every copy, and a copy with another id as an error."
- README:
  - "Threat model", integrity: "Two gaps remain … (older versions, extra
    `.cd-dir` copies)" becomes one gap (older versions); the list item
    "Moves between directories with a planted `.cd-dir` copy" goes away.
  - "Sync clients and conflict copies": the sentences about two devices
    making more than one `.cd-dir` and how to clean it up become: "A sync
    client may make a copy of a `.cd-dir` file; it holds the same id and is
    harmless (`check` reports it, you can delete it). A copy with another
    id does not come from a sync client: entries named under it are not
    shown, the drive logs a warning and `check` reports `foreign-dir-id`."
  - "Limits": the item "A directory uses at most 16 directory ids …"
    becomes: "A directory uses only the id in its own `.cd-dir`. Entries
    named under the id of a `.cd-dir` copy are hidden."
- `site/index.html`: remove the list item "Moves between directories with
  a planted `.cd-dir` copy" from "not protected".
- `CLAUDE-new.md`: section 9 (known limits), `dirstate.rs` row, status.

## 5. Tests (TDD: fail before the change unless noted)

- `fs/mod.rs`:
  - `entries_under_foreign_dir_id_copy_are_hidden`: `a/f.txt` and `b/`;
    move the real file of `f.txt` from A's real directory to B's and copy
    A's `.cd-dir` to `B/.cd-dir (1)`; after `advance_clock(RACY_WINDOW)`:
    `listed("b")` is empty, `open("b/f.txt")` gives `NotFound`, one
    warning (`foreign_copy_warnings`).
  - `same_id_copy_is_harmless`: copy B's own `.cd-dir` to
    `.cd-dir (1)`; listing as before, no warning (passes today except the
    warning counter name; it pins the rule).
  - `two_dir_ids_are_both_used` and the 16-id cap test are replaced by the
    two above (they test the old rule).
- `check.rs`: `foreign_dir_id_is_an_error` (findings `ForeignDirId` and
  `UndecryptableName`, `exit_code` 2); `same_id_copy_is_a_warning`
  (`MultipleDirIds` only, exit code 1). The old copy-cap test goes.
- `rotate.rs` or `tests/rotate.rs`:
  `rotation_does_not_adopt_entries_under_foreign_dir_id`: the planted
  move, then `rotate-key`; after it the entry is still hidden in B and
  `check` still reports it.
- `crates/crypto-drive/tests/cli.rs` or the unit tests of
  `cmd/check.rs`: the text `foreign-dir-id`.

Platforms: core and CLI code only, no `cfg(target_os)` code; the
container checks of CLAUDE.md section 7 are enough.

## 6. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | What does the drive show in a directory with a copy of another id? | The directory works; entries under the other id are hidden; one warning per mount (A). |
| 2 | What does `check` report? | Same id: `multiple-dir-ids` (warning). Other id: new `foreign-dir-id` (error); names under it: `undecryptable-name` (A). |
| 3 | Old vaults with legitimate copies of another id? | None exist (owner). |
