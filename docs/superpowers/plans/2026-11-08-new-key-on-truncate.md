# New File Key on a Cut to Size 0 – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every cut of a file to size 0 writes a new header (new
`file_nonce`, same `file_id`, write epoch), so chunks of earlier versions
no longer authenticate in the file.

**Architecture:** `OpenFile::truncate` gets the key set. For
`new_len == 0` it makes a new header, chunk cipher and size key in memory
and sets `header_dirty`. `write_out` writes the header with the next
flush, in the shrink order of `docs/format.md` 7.2. No format version
change, no FUSE change.

**Tech Stack:** Rust 2024, crate `crypto-drive-core` (`file.rs`,
`fs/files.rs`), integration test `tests/tamper.rs`.

**Spec:** `docs/superpowers/specs/2026-11-08-new-key-on-truncate-design.md`

## Global Constraints

- No format version change; golden vaults and KAT vectors stay untouched.
- New header: `FileHeader::random(keys.write_epoch(), self.header.file_id)`.
- Always on `truncate(0)`, also when the file is already empty.
- In place (no temporary file, no rename).
- Write order with `header_dirty`: chunk 0, then header (padded: header +
  new size block, 89 bytes at offset 0), then `set_len`, then (padded)
  random padding after the last chunk.
- `space_needed` adds `header_len(padded)` while `header_dirty` is set.
- A failed flush keeps the new header and `header_dirty` in memory.
- Everything in the repository in simple English; every `.rs` file keeps
  its AGPL header.
- Git is read-only for Claude (CLAUDE.md 0.2): "commit" steps mean "propose
  a commit message to the owner".
- Commands need `export PATH="$HOME/.cargo/bin:$PATH";` first.

## Review Focus

1. A cut to 0 while dirty chunks from before are still in memory: they
   must be dropped and never be written under the new key (covered:
   test `cut_to_zero_drops_unwritten_chunks`, Task 1).
2. `ftruncate(0)` through a handle (`truncate_handle`) after `unlink`: the
   new header goes into the same open real file (covered: Task 1 step 1d).
3. Two handles share one `OpenFile`: a write through the other handle
   after the cut uses the new key and reads back after reopen (covered by
   test 1 through `CryptoFs` in Task 1 step 1c, which writes through a new
   handle).
4. Rotation with two epochs: the cut file gets epoch `e + 1` and is
   readable with the key set `{e + 1}` alone (covered: test
   `cut_to_zero_writes_new_header`).
5. A failed first flush, then drop of the handle: the orphan keeps the new
   header and writes it later (covered: the retry test; the orphan path
   itself is unchanged code from R1).

---

### Task 1: New header on `truncate(0)` (core + tests)

**Files:**
- Modify: `crates/crypto-drive-core/src/file.rs` (struct `OpenFile`, `new`,
  `truncate`, `has_unwritten_changes`, `space_needed`, `write_out`; tests)
- Modify: `crates/crypto-drive-core/src/fs/files.rs:470-515` (`truncate`,
  `truncate_handle` pass `&self.keys`)
- Test: `crates/crypto-drive-core/src/file.rs` (`mod tests`),
  `crates/crypto-drive-core/tests/tamper.rs`

**Interfaces:**
- Produces: `pub fn truncate(&mut self, new_len: u64, keys: &VaultKeys) -> Result<()>`
  on `OpenFile`; field `header_dirty: bool`.

- [ ] **Step 1a: Write failing unit test `old_chunk_after_cut_to_zero_fails`** (in `file.rs` tests, `both(|padded| …)`)

```rust
let t = tmp(padded);
let mut f = new_file(&t);
f.write(0, &pattern(3 * CS + 1000)).unwrap();
f.flush().unwrap();
let at = chunk_offset(1, padded) as usize;
let full = (CHUNK_SIZE + CHUNK_OVERHEAD) as usize;
let old_chunk = std::fs::read(&t.path).unwrap()[at..at + full].to_vec();
f.truncate(0, &keys()).unwrap();
f.write(0, &vec![0xAB; 3 * CS + 1000]).unwrap();
f.flush().unwrap();
drop(f);
let mut bytes = std::fs::read(&t.path).unwrap();
bytes[at..at + full].copy_from_slice(&old_chunk);
std::fs::write(&t.path, bytes).unwrap();
let mut g = reopen(&t);
assert!(matches!(g.read(CS as u64, 16), Err(Error::AuthFailed { .. })));
```

- [ ] **Step 1b: Write failing unit tests `cut_to_zero_writes_new_header`, `cut_to_zero_drops_unwritten_chunks`, `cut_to_zero_retries_after_failed_write`** (each `both`)

  - `cut_to_zero_writes_new_header`: create with key set `{1}` and write
    `b"old"`, flush, drop; parse the first 53 bytes with
    `FileHeader::parse` (nonce `n1`); open with key set `{1, 2}` (as in
    `epoch_from_header`), `truncate(0, &both_keys)`, write `b"new"`,
    flush, drop. Assert: header nonce `!= n1`, `file_id == FILE_ID`,
    epoch `== 2`; opening with key set `{2}` only reads `b"new"`.
  - `cut_to_zero_drops_unwritten_chunks`: write 2 chunks, flush, write
    `b"zz"` at offset 0 (dirty, not flushed), `truncate(0, &keys())`,
    flush, drop; reopen: `len() == 0` and `disk_len(&t) == size(&t, 0)`.
  - `cut_to_zero_retries_after_failed_write`: write 2 chunks, flush;
    `fail_chunk_writes_after(Some(0))`; `truncate(0, &keys())` gives
    ENOSPC (`is_enospc`); `fail_chunk_writes_after(None)`; `f.len() == 0`;
    `f.flush()` is Ok; write `b"after"`, flush, drop; reopen reads
    `b"after"`.

- [ ] **Step 1c: Write failing integration test `old_chunk_after_truncate_fails`** in `tests/tamper.rs`, for `fx()` and `fx_padded()`

  Save the raw bytes of chunk 1 of `big.bin` (`chunk_offset(1, padded)`,
  length `CHUNK_SIZE + CHUNK_OVERHEAD`); `fs.truncate(&p("big.bin"), 0)`;
  `fs.open(&p("big.bin"), true, false)`, write `vec![0xCD; BIG_LEN]`,
  release; put the saved bytes back at the same offset;
  `assert_auth_failed(f.read("big.bin"))`.

- [ ] **Step 1d: Extend the test of step 1c for `truncate_handle` after unlink** (unpadded is enough)

  Open `big.bin` for writing, `unlink` it, `truncate_handle(h, 0)`, write
  `b"x"` through `h`, `read(h, 0, 16) == b"x"`, release. Assert: no error.

- [ ] **Step 2: Change only the signature, then see the tests fail**

Add the `keys: &VaultKeys` parameter to `OpenFile::truncate` without using
it yet (`let _ = keys;`), pass `&self.keys` in `fs/files.rs` and `&keys()`
in the old tests of `file.rs`.

Run: `cargo test -p crypto-drive-core cut_to_zero` and `cargo test -p crypto-drive-core --test tamper old_chunk_after_truncate_fails`
Expected: FAIL for `old_chunk_after_cut_to_zero_fails` (old data read
without an error), `cut_to_zero_writes_new_header` (same nonce) and
`old_chunk_after_truncate_fails`. The drop and retry tests may already
pass; they guard the new code paths.

- [ ] **Step 3: Implement** (remove `let _ = keys;`)

  - `OpenFile`: field `header_dirty: bool` (doc: "a new header is in
    memory but not on disk yet"), `false` in `new`.
  - `truncate(&mut self, new_len: u64, keys: &VaultKeys)`: when
    `new_len == 0`, after `check_writable` / `check_len`: build the new
    header, cipher and size key (same helpers as `create`:
    `content_key`, `ChunkCipher::new`, `size_key`), drop all cached and
    dirty chunks, set `header_dirty = true`. Then the existing logic.
    Doc comment names the reason (spec, review SEC-4).
  - `has_unwritten_changes`: also `self.header_dirty`.
  - `space_needed`: `+ header_len(padded)` while `header_dirty`.
  - `write_out`: when `header_dirty`, after the chunks and before
    `set_len`: write `header.to_bytes()` at 0; padded: header plus a new
    size block for `plain_len` (one `write_all_at` of 89 bytes at 0, the
    padded branch then does not write the size block a second time).
    Set `header_dirty = false` together with `dirty.clear()`.
    Note: the padded branch writes the size block only when
    `plain_len != disk_len`; with `header_dirty` it must be written also
    when both are 0.
  - `fs/files.rs`: `truncate` and `truncate_handle` pass `&self.keys`.
  - All other test calls of `OpenFile::truncate` in `file.rs` get
    `&keys()`.

- [ ] **Step 4: Run the tests and see them pass**

Run: `cargo test -p crypto-drive-core`
Expected: all pass, including the 4 new unit tests (8 runs with `both`)
and the new tamper test.

- [ ] **Step 5: Propose commit**

```
fix(core): new file key when a file is cut to size 0

Every version of a file used the same key, also when an app saves with
O_TRUNC, so chunks of an older version could be mixed into the current
one without an error. A cut to size 0 now writes a new file_nonce (same
file_id, write epoch). Review SEC-4; format v1 stays readable.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```

### Task 2: Docs and final checks

**Files:**
- Modify: `docs/format.md` section 7 (new SHOULD rule) and section 11
  (exception), wording from the spec section 4
- Modify: `README.md` "Threat model", paragraph "Mixing old and new
  chunks …": only files written in place without a cut to size 0
  (databases, VM images); apps that save with `O_TRUNC` or through a new
  file are not affected; plus one sentence: such files keep one key, so
  after about 2^32 chunk writes (random 96-bit nonces) a nonce collision
  becomes likely, which allows forged chunks of that file
- Modify: `site/index.html:440` list item, same narrowing in one line
- Create/overwrite: `/workspace/CLAUDE-new.md` (full content, CLAUDE.md
  0.1): `file` row (new header on `truncate(0)`), status section 11, test
  count in section 7
- Modify: spec status line ("Implemented 2026-11-08, Linux container only")

- [ ] **Step 1: Edit the docs as listed**
- [ ] **Step 2: Run the definition-of-done checks**

Run, each green:
`cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (expected: 553 + new tests passed, 0 failed, 10 ignored),
`scripts/check-license-headers.sh`.
No macOS cross-check needed (no `cfg(target_os)` code changed).

- [ ] **Step 3: Tell the owner** that `CLAUDE-new.md` changed (list) and that the site changed; propose:

```
docs: mixing old chunks is limited to files written in place

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
```
