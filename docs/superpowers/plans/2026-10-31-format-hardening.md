# Format Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace on-disk format v1 in place with a version that binds every entry's content to its name (entry id), supports key epochs and an offline `rotate-key` command, optionally pads file sizes, looks names up through a per-directory name index, and is covered by coverage-guided fuzzing.

**Architecture:**
- All format work happens in `crypto-drive-core`:
  - keys and epochs: `keys.rs`
  - key sets in the key file: `keyfile.rs`
  - marker with flags and epoch: `vault.rs`
  - header, size block and padding: `content.rs`
  - names with entry ids: `names.rs`
  - name index and binding checks: `fs/`
  - new findings: `check.rs`
  - rotation: the new `rotate.rs`
- The CLI gets `init --pad-sizes` and `rotate-key`.
- The fuzzers live in a separate nightly-only crate `fuzz/`.
- No migration: the old v1 golden files and vectors are replaced.

**Tech Stack:** Rust 1.99.1 (stable, main workspace), RustCrypto (aes-gcm, aes-siv, hkdf, hmac, sha2, argon2), fuser 0.18. Fuzzing: Rust `nightly-2026-10-15`, cargo-fuzz 0.13.2, libfuzzer-sys 0.4.13, arbitrary 1.5.0.

**Spec:**
- `docs/superpowers/specs/2026-10-31-format-hardening-design.md` (the "hardening spec")
- `docs/superpowers/specs/2026-10-31-crypto-drive-design.md` (the "base spec")

Read the hardening spec before every task. Section numbers like "HS §5.2" point into it, and "BS §4.3" into the base spec.

## Global Constraints

- **Language:** all docs, code, comments, identifiers, CLI messages and commit messages are in simple English.
- **License header:** every own `.rs`, `.sh`, `.toml`, `.py` and `.c` file starts with the project's AGPL header (`//` for Rust/C, `#` for shell/TOML/Python), exactly as in the existing files. `scripts/check-license-headers.sh` must pass.
- **Rust:** stable 1.99.1 for the main workspace, edition 2024. Fuzzing only: `nightly-2026-10-15`, pinned in `fuzz/rust-toolchain.toml`.
- **Dependencies:**
  - The main workspace adds no new crates.
  - The fuzz crate may use exactly `libfuzzer-sys = "0.4.13"`, `arbitrary = { version = "1.5.0", features = ["derive"] }` and `tempfile` (same version as the workspace).
- **Exact values (from the hardening spec):**
  - **HKDF:** salt `vault_id ‖ epoch (u32 LE)`. Labels `"crypto-drive v1 names"`, `"crypto-drive v1 content"`, `"crypto-drive v1 check"`.
  - **File keys:** `K_file` info `"crypto-drive v1 file" ‖ file_id`, `K_size` info `"crypto-drive v1 size" ‖ file_id`, both with salt `file_nonce`.
  - **Name plaintext:** `entry_id (16) ‖ NFC(name)`, AD `[parent_dir_id]`.
  - **File header:** 53 bytes `version(1)=1 ‖ epoch(u32 LE) ‖ file_nonce(32) ‖ file_id(16)`. Padded: 89 bytes, with the 36-byte size block `nonce(12) ‖ GCM(K_size, plain_len u64 LE, AD = header bytes 0–52) ‖ tag(16)`.
  - **Empty file without padding:** 81 bytes.
  - **Padding `stage(L)`:** `≤4096 → 4096`; `≤1048576 →` next power of two; else the next multiple of 1048576.
  - **`.cd-vault`:** 66 bytes, offsets `magic 0, format_version 8, max_name_length 10, flags 12 (bit 0 = pad_sizes), vault_id 14, epoch 30, tag 34`. The tag is HMAC-SHA-256 with `K_check[epoch]` over bytes 0–33.
  - **Key set (`key_set`):** `count(u8: 1|2) ‖ count × (epoch u32 LE ‖ MK 32)`. The password slot payload is 93 or 129 bytes; the AD is unchanged (BS §4.3).
  - **Epochs:** start at 1. The write epoch is the highest one.
  - **Rotation tmp file:** `.cd-rot.tmp`.
- All integers are little endian (BS §4), except `chunk_index` in the chunk AD, which stays big endian.
- **Errors and secrets** follow BS §8. Never return unauthenticated plaintext, never log clear names unless at debug level.
- **unsafe:** only where the base project already allows it. This plan adds none.
- **Platform:** code and tests must build and pass on macOS and Linux. Never use raw errno numbers.
- **Git:**
  - Branch `feat/mvp` is checked out. Never switch branches.
  - Run git with `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/workspace` and commit as `-c user.name="Marcel Joachim Kloubert" -c user.email="marcel@kloubert.dev"`.
  - Every message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. (Subagents may use the trailer their harness gives them.)
  - Never commit `.env` or `CLAUDE.md`.
- **Done for every task:**
  - `cargo fmt --check`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `scripts/check-license-headers.sh`
  - `CARGO_TARGET_DIR=/tmp/claude-1000/mac-check cargo clippy -p crypto-drive-core -p crypto-drive-fuse -p crypto-drive --lib --bins --target aarch64-apple-darwin -- -D warnings`
- **Golden files:** only made with `CRYPTO_DRIVE_WRITE_GOLDEN=1`. Make them in Task 10 only, after the KAT test passes.

## Review Focus

1. **Copying a folder with thousands of files into one drive directory** must stay linear. The name index is built once and updated in place (test in Task 7).
2. **A sync client adds, renames or deletes a file in a real directory while the drive is open.** The next lookup or readdir must show the change, because the mtime changed and the index is rebuilt (test in Task 7).
3. **A file renamed many times**, between short and long names and between directories, keeps its entry id. It stays readable, and `check` stays clean (test in Task 6).
4. **`rotate-key` is interrupted, the user mounts the drive and edits files, then runs `rotate-key` again.** The rotation finishes, and all data is intact (test in Task 9).
5. **A padded file is grown and shrunk across stage edges** (4096, powers of two, 1 MiB, 1 MiB + 1). Size, content and real length stay correct after reopening (test in Task 5).

---

## File Structure

```
crates/crypto-drive-core/src/
  keys.rs        Epoch, EntryId, MasterKey::derive(vault_id, epoch), KeySet, derive_file_key/derive_size_key (with file_id)
  keyfile.rs     password slot wraps a KeySet
  vault.rs       VaultMarker (66 B, flags, epoch), VaultKeys, InitOptions.pad_sizes, unlock/open with key sets
  content.rs     FileHeader (53 B), size block, stage(), header lengths, size math for both modes
  file.rs        OpenFile with epoch/file_id/padding
  names.rs       NameCipher with entry ids, NameKeys (several epochs)
  fs/dirstate.rs DirState with name index (Mutex<Option<Listing>>) and Mutex<SystemTime>; lookup through index
  fs/listing.rs  index build (entry id + epoch per entry), binding checks
  fs/files.rs fs/dirs.rs fs/rename.rs   in-place index updates, entry ids on create/mkdir/rename
  check.rs       new findings
  rotate.rs      rotate_key()
  testutil.rs    test_vault_opts(max_name_length, pad_sizes)
crates/crypto-drive-core/tests/  kat.rs golden.rs tamper.rs model.rs rotate.rs; golden/v1/{plain,padded}/{vault,key}
crates/crypto-drive/src/cmd/     init.rs (--pad-sizes), rotate.rs (new), passwd.rs recovery.rs recover.rs check.rs
scripts/kat/gen_vectors.py       new format
scripts/smoke-test.sh            rotate step + padded run
scripts/fuzz.sh                  run fuzz targets
fuzz/                            Cargo.toml, rust-toolchain.toml, .gitignore, seeds.sh, fuzz_targets/*.rs, corpus seeds
docs/format.md, README.md, base spec §1.2/§2/§4/§5.2/§7
```

---

### Task 1: Key epochs, entry ids and the key set

**Files:**
- Modify: `crates/crypto-drive-core/src/keys.rs`
- Modify: every caller of `MasterKey::derive`, so the workspace builds. Pass the epoch the caller has: `vault.rs` uses a constant `1` for now, and Task 3 replaces it.

**Interfaces:**
- Produces:
  ```rust
  pub type Epoch = u32;
  pub type EntryId = [u8; 16];
  impl MasterKey { pub fn derive(&self, vault_id: &VaultId, epoch: Epoch) -> SubKeys; }   // salt = vault_id ‖ epoch.to_le_bytes()
  pub struct KeySet { /* sorted by epoch, 1 or 2 entries */ }
  impl KeySet {
      pub fn single(epoch: Epoch, mk: MasterKey) -> KeySet;
      pub fn with_next(&self, mk: MasterKey) -> Result<KeySet>;   // adds write_epoch()+1; Err(InvalidArgument) if already 2
      pub fn only(&self, epoch: Epoch) -> Result<KeySet>;          // keeps one; Err(InvalidArgument) if missing
      pub fn write_epoch(&self) -> Epoch;
      pub fn epochs(&self) -> Vec<Epoch>;                          // ascending
      pub fn get(&self, epoch: Epoch) -> Option<&MasterKey>;
      pub fn len(&self) -> usize;
      pub fn encode(&self) -> zeroize::Zeroizing<Vec<u8>>;         // HS §6 key_set
      pub fn decode(bytes: &[u8]) -> Result<KeySet>;               // any rule broken => Error::WrongPassword
  }
  pub fn random_entry_id() -> Result<EntryId>;
  ```
- `derive_file_key` is changed in Task 4, not here. `KeySet` is not `Clone`, because it holds keys. Use `MasterKey::from_bytes(*mk.expose())` where a copy is really needed.

- [ ] **Step 1: Write failing tests in `keys.rs`**
  - `derive_depends_on_epoch`: same MK and vault id, epoch 1 vs 2, give different `names()`, `content()` and `check()`.
  - `key_set_round_trip`: `single(1, mk)` gives `encode().len() == 37` and decodes to the same epochs and keys. `with_next` gives epochs `[1, 2]`, length 73, `write_epoch() == 2`.
  - `key_set_rules`: `decode` gives `WrongPassword` for count 0, for count 3, for two equal epochs, for epoch 0, and for trailing bytes. `with_next` on a set of two gives `InvalidArgument`.
  - `only_keeps_one`: `with_next(...).only(2)` has `epochs() == [2]`.

- [ ] **Step 2: Run** `cargo test -p crypto-drive-core keys`. Expected: compile errors (RED).
- [ ] **Step 3: Implement** the interfaces above, and update all callers so the workspace builds.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: all pass.
- [ ] **Step 5: Commit** with message `feat(core): add key epochs, entry ids and key sets`.

---

### Task 2: Key file stores a key set

**Files:**
- Modify: `crates/crypto-drive-core/src/keyfile.rs`
- Modify: its callers (`vault.rs`, `testutil.rs`, CLI `cmd/init.rs`, `cmd/passwd.rs`, `cmd/recover.rs`, tests)

**Interfaces:**
- Consumes: `KeySet` (Task 1).
- Produces:
  ```rust
  impl KeyFile {
      pub fn new(keys: &KeySet, password: &[u8], params: Argon2Params) -> Result<Self>;
      pub fn unlock(&self, password: &[u8]) -> Result<KeySet>;                    // WrongPassword
      pub fn set_password(&mut self, keys: &KeySet, password: &[u8], params: Argon2Params) -> Result<()>;
  }
  ```
- The payload is as in HS §6, with variable length. `payload_len` must be 93 or 129 for type 1, otherwise `InvalidFormat`. The AD rule is unchanged. Unknown slots are kept as before.

- [ ] **Step 1: Update and extend the keyfile tests:**
  - `serialized_size` becomes `12 + 3 + 93` for one key and `12 + 3 + 129` for two.
  - `unlock_returns_key_set`: two epochs round trip.
  - `bad_payload_len`: 94 gives `InvalidFormat`.
  - The bit-flip, Argon2-parameter and unknown-slot tests stay and must pass.
- [ ] **Step 2: Run** `cargo test -p crypto-drive-core keyfile` and capture the RED output.
- [ ] **Step 3: Implement**, then fix the callers. During this task, `init` builds `KeySet::single(1, mk)`, and `recover` builds `KeySet::single(1, mk)`. Task 3 makes the epoch real.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): wrap a key set in the key file password slot`.

---

### Task 3: Vault marker with flags and epoch; vault keys

**Files:**
- Modify: `crates/crypto-drive-core/src/vault.rs` and `testutil.rs`
- Modify: callers in `fs/mod.rs`, `check.rs` and the CLI

**Interfaces:**
- Consumes: `KeySet`, `MasterKey::derive(vault_id, epoch)`.
- Produces:
  ```rust
  pub const MARKER_LEN: usize = 66;
  pub struct VaultMarker { pub format_version: u16, pub max_name_length: u16, pub pad_sizes: bool, pub vault_id: VaultId, pub epoch: Epoch }
  impl VaultMarker {
      pub fn to_bytes(&self, check_key: &[u8; 32]) -> [u8; 66];
      pub fn parse_unverified(b: &[u8]) -> Result<VaultMarker>;   // flags other than bit 0 => InvalidFormat{what: ".cd-vault flags"}
      pub fn verify(b: &[u8], check_key: &[u8; 32]) -> Result<()>; // WrongKey
  }
  pub struct VaultKeys { /* vault_id, BTreeMap<Epoch, SubKeys> */ }
  impl VaultKeys {
      pub fn new(vault_id: &VaultId, keys: &KeySet) -> VaultKeys;
      pub fn get(&self, epoch: Epoch) -> Option<&SubKeys>;
      pub fn write_epoch(&self) -> Epoch;
      pub fn epochs_desc(&self) -> Vec<Epoch>;
  }
  pub struct InitOptions { pub max_name_length: u16, pub argon2: Argon2Params, pub key_file: Option<PathBuf>, pub pad_sizes: bool }
  pub struct UnlockedVault { pub root_path: PathBuf, pub marker: VaultMarker, pub keys: VaultKeys }
  pub fn init_vault(vault_dir: &Path, password: &[u8], opts: &InitOptions) -> Result<MasterKey>;   // epoch 1
  pub fn unlock_vault(vault_dir: &Path, key_file: Option<&Path>, password: &[u8]) -> Result<(UnlockedVault, KeySet)>;
  pub fn open_with_key_set(vault_dir: &Path, keys: &KeySet) -> Result<UnlockedVault>;
  pub fn open_with_master_key(vault_dir: &Path, mk: &MasterKey) -> Result<UnlockedVault>;   // KeySet::single(marker.epoch, mk)
  pub fn write_marker(vault_dir: &Path, marker: &VaultMarker, check_key: &[u8; 32]) -> Result<()>;  // atomic, for rotate
  // testutil
  pub fn test_vault_opts(max_name_length: u16, pad_sizes: bool) -> (tempfile::TempDir, UnlockedVault, MasterKey);
  pub fn test_vault_padded() -> (tempfile::TempDir, UnlockedVault, MasterKey);   // 220, true
  ```
- **Unlock order:** parse the marker, then load the key file and unlock it, then verify with `K_check[marker.epoch]`. If the key set has no key for that epoch, the result is `WrongKey`.

- [ ] **Step 1: Update and extend the vault tests:**
  - The marker is 66 bytes.
  - Flag bit 1 set gives `InvalidFormat`.
  - A key set `{1, 2}` with marker epoch 1 opens, and with marker epoch 2 also opens.
  - A key set `{2}` with marker epoch 1 gives `WrongKey`.
  - `init` with `pad_sizes` sets the flag.
  - All existing marker and lock tests are kept, adapted to the new layout.
- [ ] **Step 2: RED**, then **Step 3: implement and fix the callers**. `CryptoFs` and `check` still use the write epoch's `SubKeys` until Tasks 5 and 6.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): vault marker with flags and epoch, vault keys per epoch`.

---

### Task 4: Content format: header, size block, padding stages

**Files:**
- Modify: `crates/crypto-drive-core/src/content.rs` and `keys.rs` (`derive_file_key`, new `derive_size_key`)

**Interfaces:**
- Produces:
  ```rust
  pub const HEADER_LEN: u64 = 53;
  pub const SIZE_BLOCK_LEN: u64 = 36;
  pub const PADDED_HEADER_LEN: u64 = 89;
  pub const EMPTY_FILE_LEN: u64 = 81;                  // not padded
  pub fn header_len(padded: bool) -> u64;
  pub fn stage(len: u64) -> u64;                       // HS §5.2 table; saturating at u64::MAX
  pub fn ciphertext_size(plain_len: u64, padded: bool) -> u64;   // padded => stage(89 + chunks)
  pub fn plaintext_size(cipher_len: u64) -> Result<u64>;         // not padded only (HS §5.1)
  pub fn chunk_offset(index: u64, padded: bool) -> u64;
  pub struct FileHeader { pub epoch: Epoch, pub file_nonce: [u8; 32], pub file_id: EntryId }
  impl FileHeader { pub fn random(epoch: Epoch, file_id: EntryId) -> Result<Self>; pub fn to_bytes(&self) -> [u8; 53]; pub fn parse(b: &[u8]) -> Result<Self>; }
  pub fn seal_size(size_key: &[u8; 32], header: &[u8; 53], plain_len: u64) -> Result<[u8; 36]>;
  pub fn open_size(size_key: &[u8; 32], header: &[u8; 53], block: &[u8]) -> Result<u64>;   // AuthFailed{what:"size block"}
  impl ChunkCipher { pub fn new(content_key: &[u8; 32], header: &FileHeader) -> Self; }   // K_file with file_id
  // keys.rs
  pub fn derive_file_key(content_key: &[u8; 32], file_nonce: &[u8; 32], file_id: &EntryId) -> SecretBytes<32>;
  pub fn derive_size_key(content_key: &[u8; 32], file_nonce: &[u8; 32], file_id: &EntryId) -> SecretBytes<32>;
  ```

- [ ] **Step 1: Write the tests:**
  - `stage_table`:
    - `stage(1) = 4096`, `stage(4096) = 4096`, `stage(4097) = 8192`
    - `stage(1048576) = 1048576`, `stage(1048577) = 2097152`, `stage(3_000_000) = 3145728`
    - `stage` never decreases (check 0..200_000 in steps of 997)
  - `sizes_not_padded`: `ciphertext_size(0, false) = 81`, and `plaintext_size` round trips for 0, 1, 65535, 65536, 65537, 10·65536+7.
  - `sizes_padded`: `ciphertext_size(0, true) = 4096`, `ciphertext_size(5000, true) = 8192`.
  - `header_round_trip_and_version`: version byte 2 gives `InvalidFormat`.
  - `size_block_round_trip_and_binding`: a different header byte, a flipped block bit or another key gives `AuthFailed`.
  - `file_id_is_bound`: a chunk sealed for `file_id` A does not open with a header that has `file_id` B.
  - The existing chunk tests are adapted.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.** `file.rs` and `fs` stop compiling at this point. Keep them building with a temporary adapter: `OpenFile` uses `padded = false`, epoch 1 and a random `file_id`. Task 5 replaces this. Mark the adapter with a comment `// Task 5 replaces this`.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): new file header with epoch and file id, size block and padding stages`.

---

### Task 5: OpenFile with epochs, file ids and padding

**Files:**
- Modify: `crates/crypto-drive-core/src/file.rs` and its callers in `fs/files.rs`, `fs/dirs.rs`, `fs/mod.rs`

**Interfaces:**
- Consumes: Task 3 `VaultKeys`, Task 4 content API.
- Produces:
  ```rust
  impl OpenFile {
      pub fn create(file: File, keys: &VaultKeys, file_id: EntryId, padded: bool) -> Result<OpenFile>;  // write epoch
      pub fn open(file: File, keys: &VaultKeys, padded: bool) -> Result<OpenFile>;  // epoch from header; unknown => Error::AuthFailed{what:"unknown key epoch"}
      pub fn file_id(&self) -> EntryId;
      pub fn epoch(&self) -> Epoch;
  }
  /// Reads only the header (and size block): for getattr and binding checks.
  pub fn read_file_meta(file: &File, keys: &VaultKeys, padded: bool) -> Result<(FileHeader, u64)>;
  ```
- **Padded files:**
  - Open checks the real length `== ciphertext_size(plain_len, true)`, otherwise `InvalidFormat{what:"file size"}`.
  - The flush order is chunks, then header (with a new size block), then `set_len` to the stage length. Fill new padding bytes with `random_bytes` in blocks of up to 64 KiB.
  - Shrinking cuts first and then writes random padding up to the new stage.
- **Files without padding:** behave as before, with the new 53-byte header.
- **getattr:** files without padding keep the arithmetic. Padded files use `read_file_meta`.

- [ ] **Step 1: Write the tests** in `file.rs`:
  - All existing `OpenFile` tests run twice (`padded` false and true) through a helper.
  - **Review Focus 5:** `padded_stage_edges`. Grow and shrink one file through these clear sizes: 0, 4096−89−28, 4096−89−27, 65536, 1048576−89−28·16, 1048577, 3_000_000, 10, 0. After each step: close, reopen, check `len()`, check all bytes, and check the real file length `== ciphertext_size(len, true)`.
  - `padded_length_mismatch`: one byte appended gives `InvalidFormat`.
  - `epoch_from_header`: a file created with a key set `{1, 2}` has epoch 2. Opened with keys `{2}` only, a file of epoch 1 gives `AuthFailed`.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.** Remove the Task 4 adapter.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): open files with epochs, file ids and size padding`.

---

### Task 6: Names with entry ids, name index lookup, binding checks

**Files:**
- Modify: `crates/crypto-drive-core/src/names.rs`, `fs/dirstate.rs`, `fs/listing.rs`, `fs/files.rs`, `fs/dirs.rs`, `fs/rename.rs`, `fs/mod.rs` and the fs tests that build real names by hand

**Interfaces:**
- Consumes: Tasks 3 to 5.
- Produces:
  ```rust
  // names.rs
  impl NameCipher {
      pub fn encrypt(&self, dir_id: &DirId, entry_id: &EntryId, name: &str) -> Result<String>;
      pub fn decrypt(&self, dir_id: &DirId, encoded: &str) -> Result<(EntryId, String)>;   // < 17 plaintext bytes => AuthFailed
  }
  pub struct NameKeys { /* (Epoch, NameCipher), highest epoch first */ }
  impl NameKeys {
      pub fn new(keys: &VaultKeys) -> NameKeys;
      pub fn encrypt_write(&self, dir_id: &DirId, entry_id: &EntryId, name: &str) -> Result<String>;
      pub fn decrypt_any(&self, dir_id: &DirId, encoded: &str) -> Option<(Epoch, EntryId, String)>;
  }
  // fs (crate-private)
  pub(crate) struct EntryRef { pub(crate) real: String, pub(crate) layout: Layout, pub(crate) entry_id: EntryId, pub(crate) epoch: Epoch }
  ```
- **`find`** uses the name index only (HS §3.3). Remove the probing by encrypting a name, and remove the "contains ` (conflict `" shortcut.
- **Binding** (HS §3.2), checked when an entry is used:
  - When a file is opened or read via `read_file_meta`, its header `file_id` must equal `EntryRef.entry_id`. Otherwise `AuthFailed{what: <real name>}`.
  - When a directory state is loaded, the canonical `.cd-dir` must equal the entry id from the name. Otherwise `AuthFailed`.
- **Entry ids:** `create` makes a new `random_entry_id()`, and `mkdir` uses the new `dir_id` as its entry id. `rename` encrypts the name again with the **same** entry id under the write epoch.
- **Cache:** in this task, own changes may still drop the index (`forget_listing`). Task 7 makes them update it in place.

- [ ] **Step 1: Update the tests that encrypt names by hand** to the new API, then add:
  - `names` tests:
    - round trip returns the entry id
    - a different entry id gives a different real name
    - a plaintext shorter than 17 bytes gives `AuthFailed`
    - `decrypt_any` picks the right epoch from a key set `{1, 2}`
  - `fs` tests:
    - `swapped_file_content_is_auth_failed`: copy the real content of file "a" over the real file of "b". Reading "b" gives `AuthFailed`, "a" stays fine.
    - `swapped_directories_are_auth_failed`: swap the `.cd-dir` files of two directories. `readdir` of either gives an error (`AuthFailed`), and nothing is deleted.
    - **Review Focus 3:** `many_renames_keep_entry_id`. Rename one file 20 times: short ↔ long names (vault max 64), into a subdirectory and back, onto a conflict-copy name. After each rename, reading works. At the end, `check_vault` reports no errors.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass. This includes the model test.
- [ ] **Step 5: Commit** with message `feat(core): bind names to entry ids and look names up through the index`.

---

### Task 7: In-place index updates and mtime refresh

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/dirstate.rs`, `fs/listing.rs`, `fs/files.rs`, `fs/dirs.rs`, `fs/rename.rs`

**Interfaces:**
- Produces (crate-private):
  ```rust
  impl DirState { pub(crate) fn mtime(&self) -> SystemTime; }          // mtime now in a Mutex
  impl CryptoFs {
      pub(crate) fn index_insert(&self, dir: &DirState, display: String, entry: EntryRef) -> Result<()>;
      pub(crate) fn index_remove(&self, dir: &DirState, display: &str);
      pub(crate) fn refresh_mtime(&self, dir: &DirState) -> Result<()>;   // stat_self after an own change
  }
  ```
- **create, mkdir, unlink, rmdir, rename** update the index of the affected directories and then call `refresh_mtime`. They no longer drop the parent index or invalidate the parent's cached children. Only rename of a directory still invalidates the moved subtree's paths.
- If an index is not built yet, the update does nothing; it is built on the next use.

- [ ] **Step 1: Write the tests:**
  - **Review Focus 1:** `create_many_files_builds_index_once`. Create 2000 files in one directory with a lookup before each. `listings_built()` grows by at most 1, and the run takes less than 10 s in debug mode (generous; it only catches quadratic behaviour).
  - **Review Focus 2:** `outside_changes_are_seen`. With a second `CryptoFs` on the same vault, create, rename and delete files in a directory that the first `CryptoFs` has indexed. After each change, the first one's `readdir` and `getattr` show it. Sleep 20 ms between the steps, so that file systems with a coarse mtime still see a change. A comment points to the HS §3.3 limit.
  - `own_rename_updates_both_indexes`: after renaming from directory A to directory B, `readdir` of A and B is right without a rebuild (`listings_built()` unchanged).
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `perf(core): update the name index in place on own changes`.

---

### Task 8: Check: new findings

**Files:**
- Modify: `crates/crypto-drive-core/src/check.rs` and `crates/crypto-drive/src/cmd/check.rs` (kind texts)

**Interfaces:**
- Produces: `FindingKind::{EntryIdMismatch, UnknownKeyEpoch, RotationInProgress, InvalidPadding}`. CLI texts: `entry-id-mismatch`, `unknown-key-epoch`, `rotation-in-progress`, `invalid-padding`. Severities as in HS §10. `check_vault` adds `RotationInProgress` once (with `real_path` `.cd-key`) when the vault keys have two epochs. `check_vault` still never writes.

- [ ] **Step 1: Write the tests**, one per new kind, built by changing the real tree:
  - swapped file content gives `EntryIdMismatch`
  - a file whose header says epoch 9 gives `UnknownKeyEpoch`
  - a key set `{1, 2}` gives `RotationInProgress` with exit code 1
  - a padded file grown by 1 byte gives `InvalidPadding`
  - `check_never_writes` also on a padded vault
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): report entry id, key epoch, rotation and padding findings`.

---

### Task 9: Key rotation in the core

**Files:**
- Create: `crates/crypto-drive-core/src/rotate.rs` and `crates/crypto-drive-core/tests/rotate.rs`
- Modify: `lib.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  ```rust
  pub struct RotateOptions { pub key_file: Option<PathBuf>, pub argon2: Option<Argon2Params> }
  pub struct RotateReport { pub new_recovery_key: Option<String>, pub entries_done: u64, pub new_epoch: Epoch, pub finished: bool }
  pub fn rotate_key(vault_dir: &Path, password: &[u8], opts: &RotateOptions,
                    progress: &mut dyn FnMut(u64)) -> Result<RotateReport>;
  #[cfg(any(test, feature = "test-util"))]
  pub fn set_fail_after_steps(n: Option<u64>);   // test hook: Err(Error::Io(Interrupted)) after n write steps
  ```
- The steps are exactly HS §9.2.
  - **One write step** is each of these: writing the key file, renaming a directory, each part of a file move (tmp written, new entry made, old entry removed), writing the marker, and writing the final key file.
  - `new_recovery_key` is `Some` only in the run that starts the rotation.
  - `finished` is false only when the final check finds leftovers (and then the function returns `Err`). On success it is always true.
- Takes `lock_vault` for the whole run.

- [ ] **Step 1: Write the tests** in `tests/rotate.rs`. Use the vault from `testutil` and a fixed tree: files of sizes 0, 1, 70_000 and 200_000, a long-name file, a long-name directory, a nested directory and a conflict copy. Tests:
  - `full_rotation`:
    - Afterwards `KeyFile::load(...).unlock(pw)` has epochs `[2]`, and the marker epoch is 2.
    - `open_with_master_key(old mk)` gives `WrongKey`, and the new recovery key opens the vault.
    - All content is equal, and `check_vault` reports no errors.
  - `rotation_of_padded_vault`: the same on a padded vault. All real file lengths are still stage lengths.
  - `crash_after_every_step`: for `n` in `0..total_steps`, run `rotate_key` on a fresh copy with `set_fail_after_steps(Some(n))` (it must fail), then again with `None`. Each time, content and `check` are as in `full_rotation`.
  - **Review Focus 4:** `interrupt_mount_edit_resume`. Stop after 3 steps. Open `CryptoFs` with the key set `{1, 2}`, edit one old file, create one new file and rename one file. Run `rotate_key` again: it finishes, every change is present, and `check` is clean.
  - `two_rotations_give_epoch_3`: a run on a vault whose key set has one key always starts a new rotation. Two full runs in a row give marker epoch 3, the key set `[3]` and unchanged content.
  - `locked_vault_is_refused`: a held `lock_vault` gives `AlreadyMounted`.
- [ ] **Step 2: RED.**
- [ ] **Step 3: Implement** `rotate.rs`. Reuse the fs and backing helpers, and do not duplicate the overflow-entry logic of `fs/rename.rs`: factor out a shared helper if needed.
- [ ] **Step 4: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 5: Commit** with message `feat(core): add resumable master key rotation`.

---

### Task 10: Known-answer vectors and golden vaults

**Files:**
- Modify: `scripts/kat/gen_vectors.py`, `crates/crypto-drive-core/tests/kat.rs`, `crates/crypto-drive-core/tests/golden.rs`
- Replace: `crates/crypto-drive-core/tests/golden/v1/` with `plain/` and `padded/`, each with `vault/` and `key`

**Interfaces:** none new.

- [ ] **Step 1: Update `gen_vectors.py`** (run it with the venv `/tmp/claude-1000/-workspace/0af01fce-96cc-468c-8ced-00c2993e1f6a/scratchpad/kat-venv/bin/python -I`; recreate the venv if missing: `python3 -m venv --without-pip`, bootstrap pip with get-pip, `pip install cryptography==44.0.0`). It implements HS §2–7 independently.
  - Fixed inputs: MK = 32×0x01, vault_id = 16×0x02, epoch 1 and epoch 2 (MK2 = 32×0x08), file_nonce = 32×0x03, file_id = 16×0x09, dir_id = 16×0x04, chunk nonce = 12×0x05, size nonce = 12×0x0A, password `kat-password`, Argon2 m=19456 t=2 p=1, salt 16×0x06, slot nonce 12×0x07.
  - Vectors: subkeys for epochs 1 and 2, `K_file`, `K_size`, the name of `"Rechnung März.pdf"` with entry id 16×0x09, a sealed chunk (index 3, last), a size block for `plain_len = 123456` over the header, the `.cd-vault` bytes for flags 0 and 1, a full `.cd-key` with key set `{1}` and one with `{1, 2}`, and the recovery key for MK.
- [ ] **Step 2: Update `kat.rs`** to assert the Rust code against every printed value. If a vector differs, do not change the Python to match Rust. Re-read the spec. If Rust is wrong, stop and report.
- [ ] **Step 3: Run** `cargo test -p crypto-drive-core --test kat`. Expected: pass.
- [ ] **Step 4: Update `golden.rs`:**
  - The generator writes both variants (plain, padded) with the BS §9 content, plus one file that was renamed once, so its entry id comes from creation.
  - The reader test checks both.
  - Remove the old files. Run `CRYPTO_DRIVE_WRITE_GOLDEN=1 cargo test -p crypto-drive-core --test golden -- --include-ignored`, then the normal run without the variable.
- [ ] **Step 5: Commit** with message `test(core): new known-answer vectors and golden vaults for the hardened format`.

---

### Task 11: Tamper and model tests for the new format

**Files:**
- Modify: `crates/crypto-drive-core/tests/tamper.rs` and `tests/model.rs`

- [ ] **Step 1: Tamper tests** (HS §13). Each must give `Err` and never other bytes:
  - file swap in the same directory and across directories
  - directory swap
  - header `file_id` changed, header `epoch` changed, size block changed
  - a padded file cut and grown
  - key sets with count 0, count 3 and equal epochs, built in the test by wrapping a bad key set with the real KEK. Add a `#[cfg(feature = "test-util")]` helper in `keyfile.rs`, `KeyFile::with_raw_key_set_for_tests(bytes, password, params)`, if needed.
  - The old "contents swapped" test is replaced by the file-swap tests.
- [ ] **Step 2: Model test** also runs one proptest config on `test_vault_padded()`, with the same operations. Keep the total runtime of the model test below 120 s.
- [ ] **Step 3: Run** `cargo test --workspace`. Expected: pass.
- [ ] **Step 4: Commit** with message `test(core): tamper and model tests for entry binding and padding`.

---

### Task 12: CLI: `init --pad-sizes`, `rotate-key`, key sets everywhere

**Files:**
- Modify: `crates/crypto-drive/src/main.rs`, `cmd/init.rs`, `cmd/passwd.rs`, `cmd/recovery.rs`, `cmd/recover.rs`
- Create: `cmd/rotate.rs`
- Modify: `tests/cli.rs`, `scripts/smoke-test.sh`

**Interfaces:**
- Consumes: `rotate_key`, `RotateOptions`, `RotateReport`, `unlock_vault -> (UnlockedVault, KeySet)`.
- **`rotate-key <vault-dir> [--key-file] [--password-fd] [--argon2-*] [--yes]`:**
  - It prints the HS §9.1 warning on stderr. Without `--yes` on a TTY, it asks `Continue? [y/N]`. Without `--yes` and without a TTY, it gives `Usage("add --yes to confirm the key rotation")`.
  - It prints `RECOVERY KEY: <key>` on stdout when a new rotation starts, followed by `Keep the old recovery key until the rotation has finished.` on stderr.
  - The progress line goes to stderr.
  - The exit code is 0 on success and 2 on an error.
- **Other commands:**
  - `passwd`: it unlocks the key set and keeps it all.
  - `recovery-key`: it prints the MK of `marker.epoch`.
  - `recover`: on a tag mismatch it prints exactly `the recovery key does not belong to this vault, or it is from before the last key rotation`.
  - `init --pad-sizes`: it sets the flag.

- [ ] **Step 1: Write the CLI tests:**
  - `init_with_pad_sizes`: the marker flag is set (read the byte at offset 12).
  - `rotate_key_needs_yes_without_tty`.
  - `rotate_key_rotates`: the password comes from `--password-fd 0` with `--yes`. stdout has a recovery-key line. The old recovery key with `recover` now fails with the new message, and `check` exits 0.
  - `passwd_keeps_key_set`: build a vault in the middle of a rotation with the core API (dev-dependency `crypto-drive-core` with feature `test-util`: `rotate_key` with `set_fail_after_steps(Some(2))`). After `passwd` with the CLI, the key set still has epochs `[1, 2]`.
- [ ] **Step 2: Update `scripts/smoke-test.sh`:**
  - After `check`, run `rotate-key --yes` (unmounted). Then mount, compare the checksums and unmount.
  - Run the whole script a second time on a vault made with `init --pad-sizes`. Add a loop over `PAD in "" "--pad-sizes"`, bash 3.2-safe.
- [ ] **Step 3: RED**, then implement, then GREEN (`cargo test --workspace`, `bash -n scripts/smoke-test.sh`).
- [ ] **Step 4: Commit** with message `feat(cli): add rotate-key and init --pad-sizes`.

---

### Task 13: Documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-10-31-crypto-drive-design.md` (BS §1.2, §2, §4.2–§4.8, §5.2, §7)
- Modify: `docs/format.md` and `README.md`

- [ ] **Step 1: Base spec.** Replace §4.2–§4.8 by the hardened format (HS §2–§7). In §5.2, lookup goes through the name index (HS §3.3). In §2:
  - file and directory swaps are detected
  - rollback is not detected
  - what `--pad-sizes` hides and what it does not hide
  - rotation does not undo past leaks
  - the mtime limit of HS §3.3
- [ ] **Step 2: `docs/format.md`.** The normative rewrite of the format, with MUST and MUST NOT. Include the stage table, the key set and the marker layout. The "Test vectors" section points to the new golden paths.
- [ ] **Step 3: `README.md`.**
  - `--pad-sizes` (with its cost), `rotate-key` (the multi-device rules from HS §9.1/§9.4) and the rollback limit.
  - Under "Limits": the HS §3.3 mtime limit.
- [ ] **Step 4: Verify** that every CLI flag in the README exists (`cargo run -q -p crypto-drive -- <cmd> --help`).
- [ ] **Step 5: Commit** with message `docs: document the hardened format, padding and key rotation`.

---

### Task 14: Fuzzing setup and parser targets

**Files:**
- Create: `fuzz/Cargo.toml` (own `[workspace]`, `[package.metadata] cargo-fuzz = true`), `fuzz/rust-toolchain.toml` (`channel = "nightly-2026-10-15"`), `fuzz/.gitignore` (`target/`, `corpus/*/` except seeds, `artifacts/`), `fuzz/seeds.sh`, `fuzz/fuzz_targets/{key_file,key_set,vault_marker,recovery_key,names,conflict_names,content}.rs`, `scripts/fuzz.sh`
- Modify: root `Cargo.toml` (`exclude = ["fuzz"]`), `scripts/check-license-headers.sh` (also `.py` and `.c`, and skip `fuzz/target`)

**Interfaces:**
- Consumes: the public core API. Targets that need internals use only `pub` items (`KeySet::decode`, `VaultMarker`, `NameCipher`, conflict helpers, the content functions).
- `scripts/fuzz.sh <target|all> [seconds=60]` runs `cargo +nightly-2026-10-15 fuzz run <t> fuzz/corpus/<t> -- -max_total_time=<s> -rss_limit_mb=2048 -timeout=10` from the `fuzz/` directory, and stops at the first finding with a non-zero exit.

- [ ] **Step 1: Install the tools:**
  - `rustup toolchain install nightly-2026-10-15 --profile minimal`
  - `cargo install cargo-fuzz --version 0.13.2 --locked`
  - Check: `cargo +nightly-2026-10-15 fuzz --version` prints `cargo-fuzz 0.13.2`.
- [ ] **Step 2: Write the seven parser targets** with the "must hold" rules of HS §14.3, using fixed test keys inside the targets. `seeds.sh` copies the golden files (`.cd-key`, `.cd-vault`, file contents, real names as text) and the KAT byte strings into `fuzz/corpus/<target>/seed-*`. Commit only these seeds.
- [ ] **Step 3: Run** `scripts/fuzz.sh all 60`. Expected: no finding. If something is found, fix it in the core and add the input as a `#[test]` regression test in the main workspace. Then run again.
- [ ] **Step 4: Run** the Done checks. The main workspace must not need nightly.
- [ ] **Step 5: Commit** with message `test: add cargo-fuzz setup and parser fuzz targets`.

---

### Task 15: Structured fuzz targets and the long run

**Files:**
- Create: `fuzz/fuzz_targets/hostile_tree.rs` and `fuzz/fuzz_targets/fs_ops.rs`
- Modify: `README.md` (section "Fuzzing")

- [ ] **Step 1: `hostile_tree`.**
  - An `arbitrary` struct: up to 32 entries, each with a parent index, an arbitrary real name (sometimes taken from a list such as `.cd-dir`, `.cd-name`, `.cd-content`, `.cd-cdl…`, `.cd-dir (1)`), a kind (dir or file) and up to 4 KiB of bytes.
  - It is written under a fresh test vault (plain and padded, chosen by one input bit).
  - Then it runs `check_vault`, `readdir` of every directory, `getattr` of every entry, and a full read of every file.
  - Rules: no panic, and done within the libFuzzer timeout.
- [ ] **Step 2: `fs_ops`.** An `arbitrary` list of up to 40 operations, the same set as `tests/model.rs`, run against `CryptoFs` and an in-memory model. The results must match (same rule as the model test). Use a padded vault when the first input byte is odd.
- [ ] **Step 3: Long run.** Run `scripts/fuzz.sh all 300`. Expected: no finding. Fix every finding with a regression test, then run that target again for 300 s. Put the run times and the number of executions per target into the task report.
- [ ] **Step 4: README section "Fuzzing"** (install nightly and cargo-fuzz, `scripts/fuzz.sh`).
- [ ] **Step 5: Commit** with message `test: add structured fuzz targets for hostile trees and file system operations`.

---

### Task 16: Final verification

- [ ] **Step 1: Run** the Done checks, plus `cargo deny check`, plus `bash -n scripts/smoke-test.sh scripts/fuzz.sh`. Expected: all pass.
- [ ] **Step 2: Give the owner the macOS host steps** (one command per code block):
  - `cargo test --workspace -- --include-ignored`
  - `cargo build --release`
  - `scripts/smoke-test.sh`
- [ ] **Step 3: Update** `docs/superpowers/plans/2026-10-31-crypto-drive-mvp-followups.md`: remove items this plan solved, and add new open ones.
