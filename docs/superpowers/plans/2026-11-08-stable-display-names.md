# Stable Display Names – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** While the drive is mounted, an entry keeps its display name
(plain or `(conflict N)`) as long as it exists, so a save can no longer
replace another device's entry (review ROB-1).

**Architecture:** When the listing of a directory is dropped, its
assignment (real name → display name) moves to `Index::previous`. The next
`build_listing` keeps those names first and names only new entries by the
rule of today. `EntryRef::conflict_of` lets `rename` warn when it replaces
an entry with conflict siblings.

**Tech Stack:** Rust 2024, crate `crypto-drive-core` (`fs/dirstate.rs`,
`fs/listing.rs`, `fs/rename.rs`).

**Spec:** `docs/superpowers/specs/2026-11-08-stable-display-names-design.md`

## Global Constraints

- No format change; nothing new is written to the vault or to disk.
- Assignment only in memory, per mount (`Index::previous`).
- Order in `build_listing` exactly as spec 3.2 (steps 1–4).
- `previous` holds names only (`HashMap<String, String>`, real → display),
  never used by `find`.
- Warning at `log::warn!` with the real name only, text exactly:
  `a rename replaced the entry {real}, which has sync conflict copies with the same name; check them`
- Everything in the repository in simple English; AGPL headers stay.
- Git is read-only for Claude: "commit" steps mean "propose a commit
  message to the owner".
- Commands need `export PATH="$HOME/.cargo/bin:$PATH";` first.

## Review Focus

1. A listing that is built but not stored (`skipped` entries, or an
   outdated state in `with_listing`): `previous` must stay for the next
   build, not be cleared (covered: step 1f test `previous_survives_unkept_listing`).
2. Long names (`.cd-cdl` entries) in a conflict group: the real name key is
   the `.cd-cdl` entry name, so they keep names like short ones (covered:
   the existing long-name conflict tests in `listing.rs` / `rename.rs` stay
   green; no extra planting helper for long entries).
3. Two directory ids (a `.cd-dir` copy): an entry under id 1 that had the
   plain name keeps it even though id 0 would sort first (covered by the
   rule; no extra test, existing `two_dir_ids_are_both_used` must stay
   green).
4. An entry renamed by an own change: its new real name is in the updated
   listing, so the next rebuild keeps the new name (covered: test 2).
5. `KeptDirs` weight with `previous` but no listing: counted, so the memory
   bound holds (covered by code review; existing kept-listing tests stay
   green).

---

### Task 1: Keep the assignment across rebuilds

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/dirstate.rs` (`Index`: field
  `previous`, method `drop_listing`; `shared_dir`, `forget_listing`,
  `keep_shared` weight)
- Modify: `crates/crypto-drive-core/src/fs/listing.rs` (`with_listing`,
  `build_listing(state, previous: Option<&HashMap<String, String>>)`)
- Test: `crates/crypto-drive-core/src/fs/rename.rs` (`mod tests`)

**Interfaces:**
- Produces: `Index::drop_listing(&mut self)`: moves
  `listing.entries` as real → display into `previous` (keeps an existing
  `previous` when there is no listing); `previous` cleared only when a new
  listing is stored in the index.

- [ ] **Step 1a: Test helper `plant_same_name(f: &Fx, name: &str, data: &[u8]) -> String`** in `rename.rs` tests

  Loop: `write_file(&f.fs, "plant.tmp", data)`; take its real name
  `real_tmp = f.real("plant.tmp")` and its entry id with
  `f.names.decrypt_any(&f.vault_id, &real_tmp)`; the new real name is
  `f.names.encrypt_write(&f.vault_id, &entry_id, name)`. If it sorts before
  `f.real(name)`, rename `root/real_tmp` to `root/new` with `std::fs::rename`,
  call `f.fs.advance_clock(RACY_WINDOW)` and return the new real name;
  else `f.fs.unlink(&p("plant.tmp"))` and try again (at most 64 tries).

- [ ] **Step 1b: Write failing tests 1–5 and 7 of spec section 5**

  Each starts with `write_file(&f.fs, "notes.txt", b"A")` and
  `plant_same_name(&f, "notes.txt", b"B")`, then (assertions):
  - `plain_name_stays_when_copy_arrives`:
    `listed(&f.fs, "/") == ["notes (conflict 1).txt", "notes.txt"]`,
    `read_file(.., "notes.txt") == b"A"`,
    `read_file(.., "notes (conflict 1).txt") == b"B"`.
  - `own_save_replaces_own_entry_not_the_arrived_one`: read both once,
    then `write_file("tmp", b"A2")`, `rename("tmp", "notes.txt")`;
    `notes.txt == b"A2"`, `notes (conflict 1).txt == b"B"`, the planted
    real name still exists on disk.
  - `plain_name_stays_after_racy_rebuild`: read the listing, make an own
    change in the root (`write_file("other", b"x")`), read the listing,
    `f.fs.advance_clock(RACY_WINDOW)`, read again: `notes.txt == b"A"`.
  - `conflict_numbers_stay_after_one_is_removed`: plant a second copy
    `b"C"`; read the listing; remember which content `(conflict 2)` has;
    remove the real file shown as `(conflict 1)` from outside,
    `advance_clock(RACY_WINDOW)`; `(conflict 2)` reads the same content and
    `(conflict 1)` is gone.
  - `freed_plain_name_is_not_taken_by_copy`: read the listing,
    `f.fs.unlink(&p("notes.txt"))`, `advance_clock(RACY_WINDOW)`;
    `listed == ["notes (conflict 1).txt"]`.
  - `names_follow_sort_order_after_remount`: a new `CryptoFs` from
    `open_with_master_key(&f.root, &f.mk)`: `notes.txt` reads `b"B"`
    (the planted entry sorts first).

- [ ] **Step 1c: Run and see 1–5 fail, 7 pass**

Run: `cargo test -p crypto-drive-core --lib fs::rename::tests 2>&1 | tail -40`
Expected: FAIL for the five tests (plain name went to `B`, numbers
shifted, copy took the freed name); `names_follow_sort_order_after_remount`
passes.

- [ ] **Step 1d: Implement**
  - `Index.previous: Option<HashMap<String, String>>` (doc: spec 3.1),
    `None` in the constructor.
  - `Index::drop_listing`; call it in `shared_dir` (instead of
    `index.listing = None`) and in `forget_listing`.
  - `with_listing`: `build_listing(state, index.previous.as_ref())`; set
    `index.previous = None` only on the path that stores the listing.
  - `build_listing`: steps 1–4 of spec 3.2. A `normal` entry with a
    `previous` conflict name goes to the conflict list; step 3 keeps the
    `previous` name of a conflict-list entry if it differs from its clear
    name and `entries` does not hold it yet (it came from the same real
    name, so it is a conflict name of the same clear name).
  - `keep_shared`: weight = listing entries, else `previous` entries.

- [ ] **Step 1e: Run and see them pass**

Run: `cargo test -p crypto-drive-core --lib fs::` 
Expected: all pass (also the old listing and rename tests).

- [ ] **Step 1f: Test `previous_survives_unkept_listing`** (in `listing.rs` tests, with `fail_stat_of` from the existing hook)

  Plant as above, read the listing, make one unrelated real entry fail
  its stat (`fail_stat_of(Some(real_other))`) and `advance_clock`; read
  the listing (not stored, `skipped`); `fail_stat_of(None)`; read again:
  `notes.txt` still reads `b"A"`. Run it; if it passes at once, ledger
  that the clearing rule already covers it.

- [ ] **Step 1g: Propose commit**

```
fix(fs): keep display names of same-name entries while mounted

The plain name of a clear name that two real entries share went to
the entry that sorted first, after every rebuild of the listing. It
could move to another device's entry, and the next save removed that
entry (review ROB-1). The last assignment is now kept across rebuilds;
only new entries are named by sort order.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

### Task 2: Warning on rename-over, docs, final checks

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/dirstate.rs` (`EntryRef.conflict_of`,
  `new_entry_ref` sets `None`), `fs/listing.rs` (`Found::into_entry`
  sets it for conflict names), `fs/rename.rs` (warning +
  `REPLACE_WARNINGS` test counter)
- Modify: `README.md` "Limits", `docs/format.md` section 10 item 2 (text
  in spec section 4), spec status line
- Create/overwrite: `/workspace/CLAUDE-new.md` (full content)

**Interfaces:**
- Consumes: Task 1 listing (`entries` with stable names).
- Produces: `EntryRef { .., conflict_of: Option<String> }`.

- [ ] **Step 2a: Write failing test `rename_over_entry_with_conflict_copy_warns`**: as test 1, then rename `tmp` over `notes.txt`: `replace_warnings() == 1`; then rename `tmp2` over `other.txt` (no copies): still 1.
- [ ] **Step 2b: Run, see FAIL** (`replace_warnings` does not exist → add the counter first as 0, see the assertion fail).
- [ ] **Step 2c: Implement** the field and the warning (spec 3.4). The check runs only when a target exists and is a file.
- [ ] **Step 2d: Run, see PASS**: `cargo test -p crypto-drive-core --lib fs::`.
- [ ] **Step 2e: Docs** as listed.
- [ ] **Step 2f: Definition of done**: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (562 + new, 0 failed, 10 ignored), `scripts/check-license-headers.sh`.
- [ ] **Step 2g: Propose commit**

```
feat(fs): warn when a rename replaces an entry with conflict copies

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```
