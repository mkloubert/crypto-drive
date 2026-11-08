# crypto-drive – Stable display names for entries with the same clear name

- **Date:** 2026-11-08
- **Status:** Approved by the owner (chat, 2026-11-08: names kept while
  mounted, in memory only; rename-over unchanged but with a warning; a
  freed plain name is not taken by a conflict copy). Implemented 2026-11-08,
  tested in the Linux container only
- **Author:** Marcel Joachim Kloubert
- **Source:** review 2026-11-08 (`REPORT.md`), finding ROB-1

## 1. Problem

Two real entries in one directory can have the same clear name: a sync
client made a conflict copy with a suffix, or two devices saved the same
file through a temporary file and a rename (each save gives a new entry id
and so a new real name, and the sync client sees two unrelated new files).

`build_listing` (`crates/crypto-drive-core/src/fs/listing.rs`) gives the
plain name to the entry that sorts first by `(id_index, real name)`; the
others get `<stem> (conflict N)<.ext>`, numbered in the order of the real
names. Nothing remembers the earlier choice. The listing is built again
after every outside change, after the `RACY_WINDOW` of an own change
(spec `2026-11-08-coarse-mtime-design.md`) and after a change that failed
partway: `shared_dir` and `forget_listing` set it to `None`
(`fs/dirstate.rs`).

Results:

1. **Silent data loss.** Device A has `notes.txt` (real name `RA`). The
   entry of device B (`RB`) arrives through the sync client while A is
   mounted. If `RB` sorts first, `notes.txt` now opens B's content and A's
   own entry shows as `notes (conflict 1).txt`. The next save on A (editor
   with a temporary file and a rename) replaces `notes.txt`: `rename`
   moves the new file in and removes `RB` (`replace_entry`, branch "another
   real name", `fs/rename.rs`). The sync client spreads that removal to B.
   An in-place save (`O_TRUNC`) cuts B's file instead.
2. **Shifting conflict numbers.** With copies 1, 2 and 3, removing copy 1
   makes copy 3 show as `(conflict 2)` after the next rebuild. A tool that
   writes to `(conflict 2)` by path hits another file.
3. With a planted old entry (deleted entries can be brought back, README
   "Threat model"), the attacker can pick a version that sorts first and so
   make the old version take the plain name.

## 2. Goals

1. While the drive is mounted, an entry that has a display name (plain or
   `(conflict N)`) keeps it as long as it exists in the directory, across
   every rebuild of the listing.
2. A new entry with a clear name that is already shown becomes a conflict
   copy; it never takes the name of an entry that is still there.
3. A plain name that becomes free (the entry was removed) is not given to a
   conflict copy while the drive is mounted.
4. A rename that replaces an entry with conflict siblings logs a warning.
5. No format change; nothing new is written to the vault or to disk.

Not a goal:

- Stability across a new mount, or between two machines. After a mount
  the rule of today decides (owner decision, section 6). The user then
  opens the file and sees its content, so a later save is a normal
  overwrite, not a silent loss.
- Changing what a rename over an existing name does (owner decision).
- Detecting a planted old entry (rollback stays undetected).

## 3. Design

### 3.1 Previous assignment

`Index` (`fs/dirstate.rs`) gets a field
`previous: Option<HashMap<String, String>>`: real name → display name of the
last listing. Every place that drops the listing (`shared_dir` on a new
version, `DirState::forget_listing`) moves its assignment into `previous`
instead (one helper on `Index`, `drop_listing`). If there is no listing but
already a `previous`, `previous` stays. `with_listing` passes `previous` to
`build_listing` and clears it after the new listing is stored or used.

The weight of a directory in `KeptDirs` counts the entries of the listing,
or of `previous` if there is no listing, so the memory bound stays.

`previous` holds names only (no `EntryRef`), so it cannot give a stale
entry id or layout to a lookup. It is never used by `find`.

### 3.2 Assignment order in `build_listing`

Given the classified entries (`normal`: real name without a sync suffix;
`conflicts`: with a suffix) and `previous`:

1. Every `normal` entry whose `previous` display name equals its clear name
   gets the plain name.
2. A `normal` entry whose `previous` display name is a conflict name goes
   to the conflict list (it keeps that name in step 3, goal 3). The other
   `normal` entries, which have no `previous` name, in the order of today
   `(id_index, real)`: the plain name if it is free (not taken in step 1),
   else the entry goes to the conflict list.
3. Every entry of the conflict list whose `previous` display name is a
   conflict name of its clear name and still free keeps it.
4. The other conflict entries as today: sorted by real name, the next free
   `N` per clear name.

So an entry that had `notes (conflict 1).txt` keeps it while it exists,
also when `notes.txt` was removed (goal 3). A new entry with that clear
name (no `previous` name) does get the free plain name. A plain name always wins against a conflict display name of a new
entry, as today.

Without `previous` (first listing after a mount, or a directory that left
both caches) the result is the same as today.

### 3.3 Own changes

Own changes already update the listing in place (`index_insert`,
`index_remove`). They stay as they are; the next rebuild starts from the
updated listing, so a renamed entry keeps its new name.

One exception: when `ensure_free` removed an incomplete directory (only
control files, older than 60 s) that held a name, it forgets the kept
names of that one clear name (`Index::forget_names_of`). An incomplete
directory was never a real entry, so the next entry of that name takes it,
as before. For this, `previous` holds the clear name too (`KeptName`).

### 3.4 Warning on rename-over

`EntryRef` gets `conflict_of: Option<String>`: the clear name for an entry
shown under a conflict name, `None` for a plain name and for entries made
by own changes (`new_entry_ref`).

In `CryptoFs::rename`, when a target exists and the target is replaced
(not the same real name, not a directory), the drive logs at `warn` if the
target has `conflict_of` set, or if any entry of the target listing has
`conflict_of == Some(to_name)` (NFC). Text, with only the real name:

`a rename replaced the entry {real}, which has sync conflict copies with the same name; check them`

Test counter `REPLACE_WARNINGS` (thread-local, like `EXTRA_ID_WARNINGS`).

### 3.5 Limits

- A directory whose state and kept listing are both dropped (more than
  `KEPT_DIR_ENTRIES` listing entries in total) loses its assignment; then
  the rule of today decides on the next listing.
- A running second instance or another machine can show other names.

## 4. Docs

- README "Limits": the item "If two entries in a directory have the same
  clear name, it is not defined which one gets the plain name" becomes:
  "While the drive is mounted, an entry keeps its name (plain or
  `(conflict N)`) as long as it exists; a new entry with the same name
  becomes a conflict copy, and a freed plain name is not given to a copy
  until the next mount. After a new mount the sort order of the real names
  decides. A rename over a name that has conflict copies logs a warning."
- `docs/format.md` section 10 item 2: after "`N` starts at 1 and follows the
  sort order of the real names." add "A running reader MAY keep the display
  names it already gave while those entries exist."
- `site/index.html`: no change (it does not describe which entry gets the
  plain name).
- `CLAUDE-new.md`: `fs/` row (listing), status section 11, test count.

## 5. Tests (TDD: tests 1–6 fail without the change; test 7 passes today and pins the rule after a mount)

In `crates/crypto-drive-core/src/fs/listing.rs` or `fs/rename.rs` tests.
A helper plants an entry "from another device": it creates a file under a
temporary name through `CryptoFs` (so content and file id match) and
renames the real file from outside to the encrypted real name of the
target clear name with the same entry id; it repeats with a new file until
that real name sorts **before** the existing one, then calls
`advance_clock(RACY_WINDOW)`.

1. `plain_name_stays_when_copy_arrives`: `notes.txt` with "A"; plant "B" as
   `notes.txt`; `notes.txt` reads "A", `notes (conflict 1).txt` reads "B".
2. `own_save_replaces_own_entry_not_the_arrived_one`: as 1, then write
   `tmp` with "A2" and rename it over `notes.txt`; `notes.txt` reads "A2",
   `notes (conflict 1).txt` reads "B", B's real entry still exists.
3. `plain_name_stays_after_racy_rebuild`: as 1 but the copy is planted
   right after an own change (racy mtime) and the listing is read once
   before and once after `advance_clock(RACY_WINDOW)`; names stay.
4. `conflict_numbers_stay_after_one_is_removed`: three entries with the
   same clear name; remove the one shown as `(conflict 1)` from outside;
   after the rebuild `(conflict 2)` still reads the same content.
5. `freed_plain_name_is_not_taken_by_copy`: as 1, then `unlink`
   `notes.txt`; after a rebuild the listing holds only
   `notes (conflict 1).txt`.
6. `rename_over_entry_with_conflict_copy_warns`: as 1, rename `tmp` over
   `notes.txt`: one warning; a rename over a name without copies: none.
7. `names_follow_sort_order_after_remount`: a new `CryptoFs` on the same
   vault gives the plain name to the entry that sorts first (rule of
   today, documents goal "not across mounts").

Platforms: core code only, no `cfg(target_os)` code; the container checks
of CLAUDE.md section 7 are enough.

## 6. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | How long does an assignment hold? | While mounted, in memory only (A). No state file outside the vault. |
| 2 | Rename over a name with conflict copies | Unchanged (the target is replaced), plus a `warn` log with the real name only (B). Keeping the target would leave one more copy per save. |
| 3 | A freed plain name | Not given to a conflict copy until the next mount (A). |
