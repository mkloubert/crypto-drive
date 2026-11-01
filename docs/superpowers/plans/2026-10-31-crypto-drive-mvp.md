# crypto-drive MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `crypto-drive` CLI. It mounts an encrypted vault directory as a normal read/write drive on macOS (and Linux) through FUSE.

**Architecture:** There are three crates in one Cargo workspace:
- `crypto-drive-core` holds all crypto, the on-disk format, and a path-based file system API on top of directory handles. It has no FUSE dependency and is fully tested in the Linux container.
- `crypto-drive-fuse` is a thin `fuser` adapter: an inode table, errno mapping, and mount and unmount.
- `crypto-drive` is the CLI: password input, commands, daemon mode and hardening.

**Tech Stack:**
- Rust 1.99.1, `fuser` 0.18
- RustCrypto: `aes-gcm` 0.11, `aes-siv` 0.8, `argon2` 0.6, `hkdf` 0.13, `hmac` 0.13, `sha2` 0.11
- `rustix` 1.1, `nix` 0.31, `clap` 4.6
- tests: `proptest`, benchmarks: `criterion`

**Spec:** `docs/superpowers/specs/2026-10-31-crypto-drive-design.md`. Read it before every task. Section numbers below (for example "spec §4.7") point into it.

## Global Constraints

- **Language:** all docs, code comments, identifiers, CLI messages and commit messages are in simple English.
- **License header:** every own `.rs`, `.sh` and `.toml` file starts with the AGPL header from the spec owner, shown below. Rust files use `//` and the others use `#`. `Cargo.lock` and Markdown files get no header.
  ```
  // crypto-drive
  // Copyright (C) 2026  Marcel Joachim Kloubert
  //
  // This program is free software: you can redistribute it and/or modify
  // it under the terms of the GNU Affero General Public License as published by
  // the Free Software Foundation, either version 3 of the License, or
  // (at your option) any later version.
  //
  // This program is distributed in the hope that it will be useful,
  // but WITHOUT ANY WARRANTY; without even the implied warranty of
  // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  // GNU Affero General Public License for more details.
  //
  // You should have received a copy of the GNU Affero General Public License
  // along with this program.  If not, see <http://www.gnu.org/licenses/>.
  ```
- **Crate license field:** `license = "AGPL-3.0-or-later"` in every crate.
- **Rust:** 1.99.1, set in `rust-toolchain.toml`. Edition 2024.
- **Dependency versions** go in `[workspace.dependencies]` and the committed `Cargo.lock` pins them. Use exactly these versions:
  - `fuser = "0.18.0"` (`default-features = false`; on macOS add `features = ["libfuse"]`)
  - `aes-gcm = "0.11.1"`, `aes-siv = "0.8.0"`, `argon2 = "0.6.0"`, `hkdf = "0.13.0"`, `hmac = "0.13.0"`, `sha2 = "0.11.1"`, `subtle = "2.6.1"`
  - `zeroize = "1.9.1"`, `secrecy = "0.10.3"`, `getrandom = "0.4.3"`, `base64 = "0.23.1"`, `data-encoding = "2.11.1"`, `unicode-normalization = "0.1.26"`
  - `rustix = "1.1.5"` (features `fs`, `mm`, `process`), `nix = "0.31.3"` (features `process`, `signal`, `fs`, `resource`), `libc = "0.2.191"`
  - `thiserror = "2.0.21"`, `clap = "4.6.7"` (feature `derive`), `rpassword = "7.5.4"`, `log = "0.4.34"`, `env_logger = "0.11.11"`, `lru = "0.18.5"`
  - dev: `proptest = "1.12.0"`, `tempfile = "3.27.0"`, `criterion = "0.8.2"`
  - Do not add other crates without asking the owner.
- **RustCrypto APIs changed** in the 0.11/0.13 line (`aead` 0.6, `digest` 0.11). Check docs.rs for the pinned versions. Do not copy code from older versions.
- **Unix only for now:** the core uses `rustix`. Every syscall goes through `crates/crypto-drive-core/src/backing.rs`.
- **No unsafe code**, except in `backing.rs`/`secret.rs` if `rustix` cannot avoid it. Every `unsafe` block needs a `// SAFETY:` comment.
- **No `unwrap()`/`expect()`** in non-test code, except on a `Mutex` lock (poisoning is a bug).
- **Errors:** the core returns `crypto_drive_core::Result<T>`. Never return or log plaintext that was not authenticated. Do not log clear names unless `--debug` is on.
- **Exact values from the spec:**
  - chunk size 65536, header 33 bytes, chunk overhead 28 bytes, empty file 61 bytes
  - `.cd-vault` is 60 bytes, `.cd-dir` is 16 bytes, password slot payload is 88 bytes
  - Argon2 defaults m=262144 KiB, t=3, p=4; minimums m=19456, t=2, p=1
  - `max_name_length` default 220, allowed 64…255
  - clear name max 1024 bytes; recovery key is 55 symbols in 11 groups of 5
- **Tests** use the lowest allowed Argon2 parameters (m=19456, t=2, p=1) so they stay fast.
- **Git:** the repository is owned by another uid. Run git as `git -c safe.directory=/workspace …`. Commit as `-c user.name="Marcel Joachim Kloubert" -c user.email="marcel@kloubert.dev"`. End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Work on branch `feat/mvp`. Never commit `.env`.
- **Done for every task:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace` and `scripts/check-license-headers.sh` all pass.

## Review Focus

These inputs are not in the spec's test list but are very likely to hit a real user. Each one has a test in the task that owns the code.

1. **The mountpoint is inside the vault, or the vault is inside the mountpoint.** This would make the drive recurse into itself. Expected: `mount` refuses with a clear message (test in Task 18).
2. **The same vault is mounted twice at the same time** (two terminals). The two mounts would corrupt files they both write. Expected: the second mount fails with "vault is already mounted". This uses an advisory `flock` on `.cd-vault`, so no file is written (test in Task 9).
3. **A sync client adds or removes files in the real directory while the drive is mounted.** Expected: the next `readdir`/`getattr` shows the change (mtime-based cache check; test in Task 10).
4. **Names that are not valid UTF-8** (allowed on Linux). Expected: `EINVAL` from the adapter, no panic and no lossy name (test in Task 16).
5. **The password comes from a pipe or file with a trailing newline** (`echo pw | … --password-fd 0`). Expected: exactly one trailing `\n` or `\r\n` is removed, so it unlocks the same as the TTY prompt (test in Task 15).

---

## File Structure

```
Cargo.toml                                  workspace + [workspace.dependencies]
rust-toolchain.toml                         channel = "1.99.1", components rustfmt, clippy
deny.toml                                   license allow list + advisories
.gitignore                                  /target, .env
scripts/check-license-headers.sh            header check for .rs/.sh/.toml
scripts/smoke-test.sh                       mount test on macOS/Linux
README.md, docs/format.md

crates/crypto-drive-core/
  Cargo.toml
  src/lib.rs            re-exports, module list
  src/error.rs          Error, Result
  src/secret.rs         SecretBytes<N> (zeroize + mlock), random_bytes
  src/keys.rs           MasterKey, SubKeys, derive_file_key, VaultId, DirId
  src/recovery.rs       encode/decode recovery key
  src/keyfile.rs        Argon2Params, KeyFile (format §4.3)
  src/vault.rs          constants, VaultMarker (§4.4), init_vault, unlock_vault, UnlockedVault, VaultLock
  src/names.rs          NameCipher, validate_name, BackingName, long entry names
  src/conflict.rs       prefix candidates, conflict display names
  src/content.rs        size math, FileHeader, ChunkCipher (§4.7)
  src/backing.rs        DirHandle, Stat (all syscalls)
  src/file.rs           OpenFile (random access read/write/truncate, dirty buffer)
  src/fs/mod.rs         CryptoFs, Attr, FileKind, DirEntry, StatFs, FileHandleId
  src/fs/path.rs        VPath
  src/fs/dirstate.rs    DirState, directory cache, entry lookup
  src/fs/listing.rs     readdir, conflict copies, foreign entries
  src/fs/files.rs       create/open/read/write/flush/fsync/release/truncate
  src/fs/dirs.rs        mkdir/rmdir/unlink/set_times/set_mode/getattr/statfs
  src/fs/rename.rs      rename (all cases)
  src/check.rs          check_vault, Finding
  src/testutil.rs       (feature "test-util") temp vault helpers
  tests/tamper.rs, tests/golden.rs, tests/model.rs, tests/golden/v1/...
  benches/throughput.rs

crates/crypto-drive-fuse/
  src/lib.rs            pub use; mount options builder
  src/inodes.rs         InodeTable
  src/errno.rs          to_errno
  src/adapter.rs        impl fuser::Filesystem for FuseFs
  src/mount.rs          MountRequest, mount_and_wait, unmount_command
  tests/mount.rs        #[ignore] mount tests

crates/crypto-drive/
  src/main.rs           clap definitions, dispatch, exit codes
  src/password.rs       PasswordSource, read_password, read_new_password, read_recovery_key
  src/hardening.rs      disable_core_dumps
  src/cmd/{init,passwd,recovery,recover,check,mount,unmount}.rs
  tests/cli.rs
```

---

### Task 1: Workspace, toolchain and checks

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `.gitignore`, `scripts/check-license-headers.sh`
- Create: `crates/crypto-drive-core/{Cargo.toml,src/lib.rs}`, `crates/crypto-drive-fuse/{Cargo.toml,src/lib.rs}`, `crates/crypto-drive/{Cargo.toml,src/main.rs}`

**Interfaces:**
- Produces: crate names `crypto_drive_core`, `crypto_drive_fuse`, and binary `crypto-drive`. The core has feature `test-util` (empty for now).

- [ ] **Step 1: Install the toolchain without root**

Run: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.99.1 -c rustfmt -c clippy && . "$HOME/.cargo/env" && rustc --version`
Expected: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`

- [ ] **Step 2: Install cargo-deny**

Run: `cargo install --locked cargo-deny && cargo deny --version`
Expected: a version line.

- [ ] **Step 3: Create branch `feat/mvp`** from the current branch (`docs/design-spec`).

- [ ] **Step 4: Write `scripts/check-license-headers.sh`**

It finds all `*.rs`, `*.sh` and `*.toml` files (not under `target/`, and not `Cargo.lock`). It checks that the first 15 lines equal the header with the right comment marker. It prints each bad file and exits 1, or exits 0. Run it now on an empty tree and expect exit 0.

- [ ] **Step 5: Write the workspace files**

- `Cargo.toml` has `members = ["crates/*"]`, `resolver = "3"`, `[workspace.package]` (`edition = "2024"`, `license = "AGPL-3.0-or-later"`, `rust-version = "1.99"`) and all versions from Global Constraints.
- `crypto-drive-fuse` and `crypto-drive` use `fuser` with target-specific tables: `[target.'cfg(target_os = "macos")'.dependencies] fuser = { workspace = true, features = ["libfuse"] }` and `[target.'cfg(target_os = "linux")'.dependencies] fuser = { workspace = true }`.
- `deny.toml` allows only these licenses: `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`, `MPL-2.0`, `CC0-1.0`, `0BSD`, `AGPL-3.0-or-later`. Turn on the advisories check.
- `.gitignore` holds `/target` and `.env`.
- `main.rs` prints nothing and exits 0.

- [ ] **Step 6: Verify**

Run: `cargo build --workspace && cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo fmt --check && cargo deny check && scripts/check-license-headers.sh`
Expected: everything passes.

- [ ] **Step 7: Commit**

Commit all files, including `Cargo.lock` and `LICENSE`, with message `chore: set up cargo workspace and checks`.

---

### Task 2: Errors, secrets and key derivation

**Files:**
- Create: `crates/crypto-drive-core/src/{error.rs,secret.rs,keys.rs}`
- Modify: `crates/crypto-drive-core/src/lib.rs`

**Interfaces:**
- Produces:
  ```rust
  // error.rs
  #[derive(Debug, thiserror::Error)]
  pub enum Error {
      NotFound, AlreadyExists, NotEmpty, IsADirectory, NotADirectory,
      AuthFailed { what: String },        // `what` = real (encrypted) relative path or object name
      InvalidFormat { what: String },
      WrongPassword, WrongKey, UnsupportedVersion { found: u16 },
      NameTooLong, InvalidName, InvalidArgument, Unsupported, NotPermitted,
      AlreadyMounted,
      Io(#[from] std::io::Error),
  }
  pub type Result<T> = std::result::Result<T, Error>;
  // Display texts: WrongPassword => "wrong password or damaged key file",
  // WrongKey => "the key does not belong to this vault",
  // UnsupportedVersion => "unknown format version {found}", AlreadyMounted => "vault is already mounted"

  // secret.rs
  pub struct SecretBytes<const N: usize>   // Box<[u8; N]>, zeroized on drop, mlock best effort
  impl<const N: usize> SecretBytes<N> {
      pub fn new(bytes: [u8; N]) -> Self;   // wipes nothing of the caller; caller zeroizes its copy
      pub fn random() -> Result<Self>;
      pub fn expose(&self) -> &[u8; N];
  }
  pub fn random_bytes<const N: usize>() -> Result<[u8; N]>;
  pub fn mlock_failed() -> bool;            // true if any mlock call failed (CLI prints one warning)

  // keys.rs
  pub type VaultId = [u8; 16];
  pub type DirId = [u8; 16];
  pub struct MasterKey(SecretBytes<32>);
  impl MasterKey { pub fn generate() -> Result<Self>; pub fn from_bytes(b: [u8; 32]) -> Self;
                   pub fn expose(&self) -> &[u8; 32]; pub fn derive(&self, vault_id: &VaultId) -> SubKeys; }
  pub struct SubKeys { /* names: SecretBytes<64>, content: SecretBytes<32>, check: SecretBytes<32> */ }
  impl SubKeys { pub fn names(&self) -> &[u8; 64]; pub fn content(&self) -> &[u8; 32]; pub fn check(&self) -> &[u8; 32]; }
  pub fn derive_file_key(content_key: &[u8; 32], file_nonce: &[u8; 32]) -> SecretBytes<32>;
  ```
- HKDF labels exactly as in spec §4.2: `"crypto-drive v1 names"`, `"crypto-drive v1 content"`, `"crypto-drive v1 check"`, `"crypto-drive v1 file"`.

- [ ] **Step 1: Write failing tests in `keys.rs`**

```rust
#[test] fn derive_is_deterministic() {
    let mk = MasterKey::from_bytes([7; 32]);
    assert_eq!(mk.derive(&[1; 16]).names(), mk.derive(&[1; 16]).names());
}
#[test] fn subkeys_differ_per_label_and_vault() {
    let mk = MasterKey::from_bytes([7; 32]);
    let a = mk.derive(&[1; 16]); let b = mk.derive(&[2; 16]);
    assert_ne!(a.content(), a.check());
    assert_ne!(&a.names()[..32], a.content());
    assert_ne!(a.content(), b.content());
}
#[test] fn file_keys_differ_per_nonce() {
    assert_ne!(derive_file_key(&[3; 32], &[0; 32]).expose(), derive_file_key(&[3; 32], &[1; 32]).expose());
}
#[test] fn generated_master_keys_differ() {
    assert_ne!(MasterKey::generate().unwrap().expose(), MasterKey::generate().unwrap().expose());
}
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core keys`
Expected: compile errors (types not defined).

- [ ] **Step 3: Implement `error.rs`, `secret.rs` and `keys.rs`**

- `secret.rs` calls `rustix::mm::mlock` on the boxed array. On error, it sets a global `AtomicBool` and goes on. On drop it calls `munlock` and then zeroizes.
- `derive` uses `Hkdf::<Sha512>::new(Some(vault_id), mk)` and calls `expand` three times.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core keys`
Expected: 4 passed.

- [ ] **Step 5: Commit** with message `feat(core): add errors, secret memory and key derivation`.

---

### Task 3: Recovery key

**Files:**
- Create: `crates/crypto-drive-core/src/recovery.rs`

**Interfaces:**
- Consumes: `MasterKey` (Task 2).
- Produces: `pub fn encode_recovery_key(mk: &MasterKey) -> String` and `pub fn decode_recovery_key(input: &str) -> Result<MasterKey>`. A bad symbol, a bad length or a bad checksum gives `Error::InvalidFormat { what: "recovery key" }`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn format_is_11_groups_of_5() {
    let s = encode_recovery_key(&MasterKey::from_bytes([0xAB; 32]));
    assert_eq!(s.len(), 65);
    assert!(s.split('-').all(|g| g.len() == 5));
    assert!(s.chars().all(|c| c == '-' || "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c)));
}
#[test] fn round_trip_with_sloppy_input() {
    let mk = MasterKey::from_bytes([0x5C; 32]);
    let s = encode_recovery_key(&mk).to_lowercase().replace('-', " ");
    assert_eq!(decode_recovery_key(&s).unwrap().expose(), mk.expose());
}
#[test] fn confusable_letters_are_mapped() {
    // build the key, replace every '1' with 'l' and every '0' with 'O'; it must still decode
}
#[test] fn single_symbol_change_is_rejected() {
    // change one symbol in the middle; expect Err(Error::InvalidFormat { .. })
}
#[test] fn wrong_length_is_rejected() { assert!(decode_recovery_key("ABCDE").is_err()); }
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core recovery`
Expected: FAIL (not defined).

- [ ] **Step 3: Implement**

- Checksum = `SHA-256(MK ‖ "crypto-drive v1 recovery")[0..2]`.
- Encode with a `data_encoding::Specification`: symbols `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no padding, `check_trailing_bits = true`. That gives 34 bytes → 55 symbols.
- Before decoding: drop spaces and `-`, convert to upper case, map `I`/`L`→`1` and `O`→`0`, and require exactly 55 symbols.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core recovery`
Expected: 5 passed.

- [ ] **Step 5: Commit** with message `feat(core): add recovery key encoding`.

---

### Task 4: Key file

**Files:**
- Create: `crates/crypto-drive-core/src/keyfile.rs`

**Interfaces:**
- Consumes: `MasterKey`, `random_bytes`, `Error`.
- Produces:
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub struct Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }
  impl Default for Argon2Params   // 262144, 3, 4
  impl Argon2Params {
      pub const MIN: Argon2Params = Argon2Params { m_kib: 19456, t: 2, p: 1 };
      pub fn validate(&self) -> Result<()>;      // below MIN => Error::InvalidArgument
      pub fn is_below_default(&self) -> bool;
  }
  pub struct KeyFile { /* slots: Vec<Slot>; Slot = Password{..} | Unknown{slot_type, payload} */ }
  impl KeyFile {
      pub fn new(mk: &MasterKey, password: &[u8], params: Argon2Params) -> Result<Self>;
      pub fn unlock(&self, password: &[u8]) -> Result<MasterKey>;           // Error::WrongPassword
      pub fn set_password(&mut self, mk: &MasterKey, password: &[u8], params: Argon2Params) -> Result<()>;
          // removes all password slots, adds one new slot, keeps Unknown slots
      pub fn to_bytes(&self) -> Vec<u8>;
      pub fn from_bytes(bytes: &[u8]) -> Result<Self>;  // bad magic/length => InvalidFormat, version != 1 => UnsupportedVersion
      pub fn load(path: &Path) -> Result<Self>;
      pub fn save_new(&self, path: &Path) -> Result<()>;      // fails with AlreadyExists if path exists
      pub fn save_replace(&self, path: &Path) -> Result<()>;  // atomic replace
  }
  ```
- The layout and the AD are exactly as in spec §4.3. The AD does not contain `slot_count`.
- Atomic write: write `<name>.tmp` in the same directory with mode 0600, `fsync`, `rename`, then `fsync` the directory. `save_new` uses `create_new` semantics on the final path check. Use `std::fs` here. The key file is outside the vault tree logic, so `backing.rs` is not needed.

- [ ] **Step 1: Write failing tests**

```rust
fn p() -> Argon2Params { Argon2Params::MIN }
#[test] fn unlock_round_trip() { /* new(mk,"pw") then unlock("pw") == mk */ }
#[test] fn wrong_password() { /* unlock("nope") => Err(Error::WrongPassword) */ }
#[test] fn serialized_size() { assert_eq!(KeyFile::new(&mk, b"pw", p()).unwrap().to_bytes().len(), 12 + 3 + 88); }
#[test] fn changed_argon2_params_fail() { /* flip byte at offset 12+3+0 (m_kib) => unlock gives WrongPassword */ }
#[test] fn any_bit_flip_fails() { /* for every byte offset >= 12: flip one bit; from_bytes or unlock must Err */ }
#[test] fn unknown_slot_is_kept_and_skipped() {
    // append a slot (type 9, len 3, b"xyz"), fix slot_count; unlock still works;
    // set_password keeps the type-9 slot in to_bytes()
}
#[test] fn set_password_replaces_old() { /* old pw => WrongPassword, new pw => mk */ }
#[test] fn params_below_minimum_rejected() { assert!(Argon2Params { m_kib: 1024, t: 2, p: 1 }.validate().is_err()); }
#[test] fn save_new_refuses_existing_file() { /* second save_new => Err(AlreadyExists) */ }
#[test] fn saved_file_mode_is_0600() { /* std::os::unix::fs::PermissionsExt */ }
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core keyfile`
Expected: FAIL.

- [ ] **Step 3: Implement** `keyfile.rs` as described above. The KEK is `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m, t, p, Some(32)))` with `hash_password_into`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core keyfile`
Expected: 10 passed.

- [ ] **Step 5: Commit** with message `feat(core): add password-protected key file with slots`.

---

### Task 5: Names

**Files:**
- Create: `crates/crypto-drive-core/src/names.rs`

**Interfaces:**
- Consumes: `DirId`, `Error`.
- Produces:
  ```rust
  pub const MAX_CLEAR_NAME_BYTES: usize = 1024;
  pub const LONG_PREFIX: &str = ".cd-cdl";
  pub fn validate_name(name: &str) -> Result<()>;      // empty/"."/".."/'/'/NUL => InvalidName; > 1024 B => NameTooLong
  pub struct NameCipher { /* Aes256Siv key */ }
  impl NameCipher {
      pub fn new(names_key: &[u8; 64]) -> Self;
      pub fn encrypt(&self, dir_id: &DirId, name: &str) -> Result<String>;   // validates, NFC, B64
      pub fn decrypt(&self, dir_id: &DirId, encoded: &str) -> Result<String>;
          // bad B64 => InvalidFormat; failed auth or not UTF-8 => AuthFailed { what: encoded }
  }
  pub enum BackingName { Short(String), Long { entry: String, full: String } }
  pub fn to_backing_name(encoded: String, max_name_length: u16) -> BackingName;
  pub fn long_entry_name(encoded: &str) -> String;     // ".cd-cdl" + B64(SHA-256(encoded))
  pub fn is_b64_char(c: char) -> bool;
  ```

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn round_trip_unicode() { /* "Rechnung März 🧾.pdf" encrypt then decrypt is equal */ }
#[test] fn nfd_and_nfc_encrypt_the_same() { assert_eq!(c.encrypt(&d, "e\u{301}").unwrap(), c.encrypt(&d, "\u{e9}").unwrap()); }
#[test] fn depends_on_dir_id() { /* same name, dir ids [1;16] vs [2;16] => different */ }
#[test] fn wrong_dir_id_fails_auth() { /* decrypt with other dir id => Err(AuthFailed{..}) */ }
#[test] fn output_has_no_dot_and_only_b64() { /* all chars is_b64_char */ }
#[test] fn invalid_names() { for n in ["", ".", "..", "a/b", "a\0b"] { assert!(matches!(validate_name(n), Err(Error::InvalidName))); } }
#[test] fn too_long() { assert!(matches!(validate_name(&"a".repeat(1025)), Err(Error::NameTooLong))); assert!(validate_name(&"a".repeat(1024)).is_ok()); }
#[test] fn overflow_limit_is_inclusive() {
    let e220 = "A".repeat(220); assert!(matches!(to_backing_name(e220, 220), BackingName::Short(_)));
    let e221 = "A".repeat(221); match to_backing_name(e221.clone(), 220) {
        BackingName::Long { entry, full } => { assert_eq!(entry.len(), 50); assert!(entry.starts_with(".cd-cdl")); assert_eq!(full, e221); }
        _ => panic!() }
}
#[test] fn cd_prefixed_clear_name_is_fine() { /* ".cd-vault" encrypts and decrypts, and the output has no dot */ }
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core names`
Expected: FAIL.

- [ ] **Step 3: Implement** `names.rs` with `aes_siv::Aes256Siv`. Pass the AD as the single header `[dir_id]`. Use `base64::engine::general_purpose::URL_SAFE_NO_PAD`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core names`
Expected: 9 passed.

- [ ] **Step 5: Commit** with message `feat(core): add AES-SIV name encryption and overflow names`.

---

### Task 6: Conflict copy helpers

**Files:**
- Create: `crates/crypto-drive-core/src/conflict.rs`

**Interfaces:**
- Consumes: `is_b64_char`, `LONG_PREFIX` (Task 5).
- Produces:
  ```rust
  pub const MIN_ENCODED_LEN: usize = 22;          // 16-byte SIV tag in B64
  /// (prefix, suffix) pairs for a real entry name that does not start with '.',
  /// longest prefix first. Prefixes are only B64 chars, len >= MIN_ENCODED_LEN.
  /// The first pair is (whole B64 run, rest).
  pub fn short_candidates(real: &str) -> Vec<(&str, &str)>;
  /// For ".cd-cdl" + 43 B64 chars + suffix: Some((entry, suffix)); suffix may be "".
  pub fn long_candidate(real: &str) -> Option<(&str, &str)>;
  /// "Report.pdf", 1 => "Report (conflict 1).pdf"; "README", 2 => "README (conflict 2)";
  /// ".bashrc", 1 => ".bashrc (conflict 1)"; "a.tar.gz", 1 => "a.tar (conflict 1).gz"
  pub fn conflict_display_name(clear: &str, n: u32) -> String;
  ```

- [ ] **Step 1: Write failing tests** using a valid 30-character B64 token `T` and these suffixes:

```rust
#[test] fn suffixes_of_real_clients() {
    let t = "AbCdEfGhIjKlMnOpQrStUvWxYz0123";
    for (real, suffix) in [
        (format!("{t}.sync-conflict-20261031-123456-ABCDEFG"), ".sync-conflict-20261031-123456-ABCDEFG"), // Syncthing
        (format!("{t} (conflicted copy 2026-10-31 123456)"), " (conflicted copy 2026-10-31 123456)"),     // Nextcloud
        (format!("{t} (Marcel's conflicted copy 2026-10-31)"), " (Marcel's conflicted copy 2026-10-31)"), // Dropbox
        (format!("{t} 2"), " 2"),                                                                          // iCloud
        (format!("{t} (1)"), " (1)"),                                                                      // Google Drive
    ] { assert!(short_candidates(&real).contains(&(t, suffix))); }
}
#[test] fn b64_only_suffix_gives_all_prefixes() {
    let real = "AbCdEfGhIjKlMnOpQrStUvWxYz0123-DESKTOP1";  // OneDrive
    let c = short_candidates(real);
    assert_eq!(c[0], (real, ""));
    assert!(c.contains(&("AbCdEfGhIjKlMnOpQrStUvWxYz0123", "-DESKTOP1")));
    assert!(c.windows(2).all(|w| w[0].0.len() > w[1].0.len()));
}
#[test] fn short_tokens_are_ignored() { assert!(short_candidates("abc (1)").is_empty()); }
#[test] fn long_candidate_works() { /* ".cd-cdl" + 43 chars + " (1)" => Some((first 50 chars, " (1)")) ; 42 chars => None */ }
#[test] fn display_names() { /* the four examples from the doc comment */ }
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core conflict`
Expected: FAIL.

- [ ] **Step 3: Implement.** The extension split is at the last `.` that is not at index 0.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core conflict`
Expected: 5 passed.

- [ ] **Step 5: Commit** with message `feat(core): add sync conflict copy detection helpers`.

---

### Task 7: Content format

**Files:**
- Create: `crates/crypto-drive-core/src/content.rs`

**Interfaces:**
- Consumes: `derive_file_key`, `random_bytes`, `Error`.
- Produces:
  ```rust
  pub const CHUNK_SIZE: u64 = 65536;
  pub const HEADER_LEN: u64 = 33;
  pub const CHUNK_OVERHEAD: u64 = 28;
  pub const EMPTY_FILE_LEN: u64 = 61;
  pub fn ciphertext_size(plain_len: u64) -> u64;
  pub fn plaintext_size(cipher_len: u64) -> Result<u64>;   // InvalidFormat for invalid sizes (spec §4.7)
  pub fn chunk_count(plain_len: u64) -> u64;               // max(1, ceil(plain_len / CHUNK_SIZE))
  pub fn chunk_offset(index: u64) -> u64;                  // HEADER_LEN + index * (CHUNK_SIZE + CHUNK_OVERHEAD)
  pub struct FileHeader { pub file_nonce: [u8; 32] }
  impl FileHeader { pub fn random() -> Result<Self>; pub fn to_bytes(&self) -> [u8; 33];
                    pub fn parse(b: &[u8]) -> Result<Self>; }  // version != 1 or short => InvalidFormat
  pub struct ChunkCipher { /* Aes256Gcm with K_file */ }
  impl ChunkCipher {
      pub fn new(content_key: &[u8; 32], header: &FileHeader) -> Self;
      pub fn seal(&self, index: u64, is_last: bool, plain: &[u8]) -> Result<Vec<u8>>;   // nonce ‖ ct ‖ tag
      pub fn open(&self, index: u64, is_last: bool, sealed: &[u8]) -> Result<Vec<u8>>;  // AuthFailed { what: "chunk <index>" }
  }
  ```

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn sizes() {
    assert_eq!(ciphertext_size(0), 61);
    assert_eq!(ciphertext_size(1), 33 + 28 + 1);
    assert_eq!(ciphertext_size(65536), 33 + 28 + 65536);
    assert_eq!(ciphertext_size(65537), 33 + 2 * 28 + 65537);
    for n in [0, 1, 65535, 65536, 65537, 10 * 65536, 10 * 65536 + 7] { assert_eq!(plaintext_size(ciphertext_size(n)).unwrap(), n); }
}
#[test] fn invalid_sizes() {
    for c in [0, 33, 60] { assert!(plaintext_size(c).is_err()); }
    assert!(plaintext_size(33 + 65536 + 28 + 28).is_err());   // second chunk is empty
}
#[test] fn seal_open_round_trip_and_fresh_nonce() { /* seal twice => different bytes; both open to same plain */ }
#[test] fn index_and_last_flag_are_bound() {
    // sealed with (3, false): open(4, false) and open(3, true) both => Err(AuthFailed{..})
}
#[test] fn other_file_key_fails() { /* other header nonce => AuthFailed */ }
#[test] fn header_version_checked() { /* first byte 2 => InvalidFormat */ }
```

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core content`
Expected: FAIL.

- [ ] **Step 3: Implement.** The AD is `index.to_be_bytes() ‖ [is_last as u8]`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core content`
Expected: 6 passed.

- [ ] **Step 5: Commit** with message `feat(core): add chunked AES-GCM content format`.

---

### Task 8: Backing directory handles

**Files:**
- Create: `crates/crypto-drive-core/src/backing.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum Kind { File, Dir, Other }
  #[derive(Clone, Debug)] pub struct Stat { pub kind: Kind, pub size: u64, pub mode: u32, pub uid: u32, pub gid: u32,
      pub atime: SystemTime, pub mtime: SystemTime, pub ctime: SystemTime, pub dev: u64, pub ino: u64 }
  pub struct DirHandle { /* OwnedFd */ }
  impl DirHandle {
      pub fn open_root(path: &Path) -> Result<DirHandle>;
      pub fn open_dir(&self, name: &str) -> Result<DirHandle>;           // O_DIRECTORY|O_NOFOLLOW
      pub fn stat_self(&self) -> Result<Stat>;
      pub fn stat(&self, name: &str) -> Result<Stat>;                    // no follow; ENOENT => Error::NotFound
      pub fn list(&self) -> Result<Vec<String>>;                         // no "."/".."; non-UTF-8 names skipped with log::warn
      pub fn open_file(&self, name: &str, write: bool) -> Result<std::fs::File>;
      pub fn create_file(&self, name: &str, mode: u32) -> Result<std::fs::File>;  // O_CREAT|O_EXCL; EEXIST => AlreadyExists
      pub fn read_small(&self, name: &str, max: usize) -> Result<Vec<u8>>;        // longer => InvalidFormat
      pub fn write_atomic(&self, name: &str, data: &[u8], mode: u32) -> Result<()>; // "<name>.tmp", fsync, renameat, fsync dir
      pub fn mkdir(&self, name: &str, mode: u32) -> Result<()>;
      pub fn rmdir(&self, name: &str) -> Result<()>;                     // ENOTEMPTY => NotEmpty
      pub fn unlink(&self, name: &str) -> Result<()>;
      pub fn rename(&self, from: &str, to_dir: &DirHandle, to: &str) -> Result<()>;
      pub fn set_times(&self, name: &str, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> Result<()>;
      pub fn set_mode(&self, name: &str, mode: u32) -> Result<()>;
      pub fn statvfs(&self) -> Result<rustix::fs::StatVfs>;
      pub fn lock_exclusive_nonblocking(file: &std::fs::File) -> Result<()>;  // flock LOCK_EX|LOCK_NB; EWOULDBLOCK => AlreadyMounted
  }
  ```
- `io::Error` values map to `Error::Io`, except ENOENT → `NotFound`, EEXIST → `AlreadyExists`, ENOTEMPTY → `NotEmpty`, ENOTDIR → `NotADirectory`, EISDIR → `IsADirectory`.

- [ ] **Step 1: Write failing tests** in a `tempfile::TempDir`:
  - `mkdir` + `open_dir` + `list`
  - `create_file` twice gives `AlreadyExists`
  - `write_atomic` then `read_small` round trip, and no `.tmp` is left
  - `rename` across two handles
  - `rmdir` of a non-empty directory gives `NotEmpty`
  - `stat` of a missing entry gives `NotFound`
  - `set_mode` 0o640 is seen in `stat`
  - `set_times` sets the mtime to `UNIX_EPOCH + 1_000_000 s`
  - the second `lock_exclusive_nonblocking` on another `File` of the same path gives `AlreadyMounted`

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core backing`
Expected: FAIL.

- [ ] **Step 3: Implement** with `rustix::fs` (`openat`, `statat` with `AtFlags::SYMLINK_NOFOLLOW`, `Dir`, `mkdirat`, `unlinkat`, `renameat`, `utimensat`, `chmodat`, `fstatvfs`, `flock`). Convert to `std::fs::File` with `File::from(OwnedFd)`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core backing`
Expected: 9 passed.

- [ ] **Step 5: Commit** with message `feat(core): add directory-handle based backing layer`.

---

### Task 9: Vault marker, init, unlock and lock

**Files:**
- Create: `crates/crypto-drive-core/src/vault.rs`, `crates/crypto-drive-core/src/testutil.rs`

**Interfaces:**
- Consumes: `MasterKey`, `SubKeys`, `KeyFile`, `Argon2Params`, `DirHandle`, `random_bytes`.
- Produces:
  ```rust
  pub const VAULT_FILE: &str = ".cd-vault"; pub const KEY_FILE: &str = ".cd-key";
  pub const DIR_FILE: &str = ".cd-dir"; pub const NAME_FILE: &str = ".cd-name";
  pub const CONTENT_FILE: &str = ".cd-content"; pub const CONTROL_PREFIX: &str = ".cd-";
  pub const DEFAULT_MAX_NAME_LENGTH: u16 = 220;
  pub struct VaultMarker { pub format_version: u16, pub max_name_length: u16, pub vault_id: VaultId }
  impl VaultMarker {
      pub fn to_bytes(&self, keys: &SubKeys) -> [u8; 60];
      pub fn parse_unverified(b: &[u8]) -> Result<VaultMarker>;   // magic/len => InvalidFormat, version => UnsupportedVersion
      pub fn verify(b: &[u8], keys: &SubKeys) -> Result<()>;      // tag mismatch => WrongKey (constant-time)
  }
  pub struct InitOptions { pub max_name_length: u16, pub argon2: Argon2Params, pub key_file: Option<PathBuf> }
  pub fn key_file_path(vault_dir: &Path, key_file: Option<&Path>) -> PathBuf;
  pub fn init_vault(vault_dir: &Path, password: &[u8], opts: &InitOptions) -> Result<MasterKey>;
      // dir must not exist or be empty (else AlreadyExists); max_name_length 64..=255 (else InvalidArgument)
      // writes .cd-vault, then KeyFile::save_new; returns MK for the recovery key
  pub struct UnlockedVault { pub root_path: PathBuf, pub marker: VaultMarker, pub keys: SubKeys }
  pub fn open_with_master_key(vault_dir: &Path, mk: &MasterKey) -> Result<UnlockedVault>;
  pub fn unlock_vault(vault_dir: &Path, key_file: Option<&Path>, password: &[u8]) -> Result<(UnlockedVault, MasterKey)>;
      // order: read marker (version check) -> load key file -> unlock (WrongPassword) -> derive -> verify (WrongKey)
  pub struct VaultLock { /* File holding flock on .cd-vault */ }
  pub fn lock_vault(vault_dir: &Path) -> Result<VaultLock>;    // AlreadyMounted if held elsewhere

  // testutil.rs, #[cfg(feature = "test-util")] pub mod testutil
  pub const TEST_PASSWORD: &[u8] = b"test-password";
  pub fn test_vault() -> (tempfile::TempDir, UnlockedVault);              // Argon2Params::MIN, default max name len
  pub fn test_vault_with(max_name_length: u16) -> (tempfile::TempDir, UnlockedVault);
  ```
- `tempfile` becomes an optional dependency that the `test-util` feature turns on. The core's `[dev-dependencies]` enable its own `test-util`.

- [ ] **Step 1: Write failing tests**
  - `init` then `unlock_vault` with the right password works, and `marker.max_name_length == 220`.
  - The wrong password gives `WrongPassword`.
  - `init` into a non-empty directory gives `AlreadyExists`.
  - `--key-file` outside the vault: the vault has only `.cd-vault`, and unlock works with that key file.
  - A key file from another vault gives `WrongKey`.
  - The marker is exactly 60 bytes.
  - A flipped bit in the tag gives `WrongKey`.
  - Bytes 8..10 set to `2` give `UnsupportedVersion { found: 2 }`, and nothing in the directory changed (compare the listing and mtimes).
  - `max_name_length` 63 and 256 give `InvalidArgument`.
  - **Review Focus 2:** `lock_vault` twice on the same directory: the second gives `AlreadyMounted`. After the first lock is dropped, it works again.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core vault`
Expected: FAIL.

- [ ] **Step 3: Implement `vault.rs` and `testutil.rs`.**

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core vault`
Expected: 10 passed.

- [ ] **Step 5: Commit** with message `feat(core): add vault marker, init, unlock and mount lock`.

---

### Task 10: CryptoFs base: paths, directory state, mkdir, readdir, getattr

**Files:**
- Create: `crates/crypto-drive-core/src/fs/{mod.rs,path.rs,dirstate.rs,listing.rs,dirs.rs}`

**Interfaces:**
- Consumes: `UnlockedVault`, `NameCipher`, `to_backing_name`, `long_entry_name`, conflict helpers, `DirHandle`, `plaintext_size`.
- Produces:
  ```rust
  // path.rs
  #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
  pub struct VPath(Vec<String>);
  impl VPath { pub fn root() -> Self; pub fn parse(s: &str) -> Result<Self>;   // "/a/b" or "a/b"; validates every part
               pub fn join(&self, name: &str) -> Result<Self>; pub fn parent(&self) -> Option<VPath>;
               pub fn name(&self) -> Option<&str>; pub fn is_root(&self) -> bool;
               pub fn starts_with(&self, other: &VPath) -> bool;
               pub fn replace_prefix(&self, from: &VPath, to: &VPath) -> Option<VPath>; }
  // mod.rs
  #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub enum FileKind { File, Directory }
  #[derive(Clone, Debug)] pub struct Attr { pub kind: FileKind, pub size: u64, pub mode: u32, pub uid: u32, pub gid: u32,
      pub atime: SystemTime, pub mtime: SystemTime, pub ctime: SystemTime, pub nlink: u32 }
  #[derive(Clone, Debug, PartialEq, Eq)] pub struct DirEntry { pub name: String, pub kind: FileKind }
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)] pub struct FileHandleId(pub u64);
  pub struct StatFs { pub blocks: u64, pub bfree: u64, pub bavail: u64, pub files: u64, pub ffree: u64, pub bsize: u32, pub namelen: u32, pub frsize: u32 }
  pub struct CryptoFs { /* Send + Sync */ }
  impl CryptoFs {
      pub fn new(vault: UnlockedVault) -> Result<CryptoFs>;
      pub fn getattr(&self, path: &VPath) -> Result<Attr>;
      pub fn readdir(&self, path: &VPath) -> Result<Vec<DirEntry>>;   // sorted by name, no "."/".."
      pub fn mkdir(&self, path: &VPath, mode: u32) -> Result<Attr>;
      pub fn statfs(&self) -> Result<StatFs>;                         // namelen = 255
  }
  ```
- Inner types (crate-private, used by Tasks 11 to 13):
  - `DirState { handle: Arc<DirHandle>, dir_ids: Vec<DirId> /* canonical first */, mtime: SystemTime, listing: Mutex<Option<Listing>> }`
  - `Listing { entries: BTreeMap<String /*display*/, EntryRef> }`
  - `EntryRef { real: String, layout: Layout }`
  - `Layout { ShortFile, ShortDir, LongFile, LongDir }`
  - `fn dir_state(&self, path: &VPath) -> Result<Arc<DirState>>`
  - `fn find(&self, parent: &DirState, name: &str) -> Result<EntryRef>`
  - `fn new_entry_name(&self, parent: &DirState, name: &str) -> Result<BackingName>`
  - `fn invalidate(&self, path: &VPath)`, which drops the path and every cached path under it
- **`find` algorithm:**
  1. Encrypt `name` with the canonical `dir_id`. Stat the short name, or the long entry (and check its `.cd-name` equals the full name).
  2. If not found, repeat with the other `dir_id`s.
  3. If not found, build the listing and look up the display name (this finds conflict copies).
  4. Otherwise `NotFound`.
- **Directory state:**
  - Read `.cd-dir` (16 bytes) plus every other entry whose name starts with `.cd-dir`, is not `.cd-dir.tmp` and is 16 bytes long.
  - No `.cd-dir` and only control entries: remove the directory and give `NotFound`. No `.cd-dir` but other entries: `InvalidFormat`.
  - The cache is `lru::LruCache<VPath, Arc<DirState>>` with capacity 1024. On every cache hit, compare `handle.stat_self().mtime` with the stored mtime. If they differ, rebuild the state.
- **Listing algorithm** (spec §5.3):
  - Skip names starting with `.cd-` unless `long_candidate` returns `Some`. Skip other names starting with `.`.
  - For short names, try `short_candidates` in order with every `dir_id`. The first that decrypts wins.
  - Empty suffix: a normal entry. Non-empty suffix: a conflict entry. Conflict entries get `conflict_display_name(clear, n)`, with n counted per clear name in the sort order of the real names.
  - A display name that collides with an existing name gets the next n.
- **mkdir** (spec §5.5):
  1. Create the real directory with `mode`. For a long name, it is the `.cd-cdl` entry.
  2. For a long name, `write_atomic(".cd-name")` inside it.
  3. `write_atomic(".cd-dir", random 16 bytes, 0o600)`.
  4. Invalidate the parent.
- **getattr:**
  - A file's size is `plaintext_size(real size)`. An invalid size gives `InvalidFormat`. Task 11 adds the open-file override.
  - A directory's size is the real size.
  - The root gives the attributes of the vault root directory.
  - `nlink` is 1 for files and 2 for directories.

- [ ] **Step 1: Write failing tests** in `fs/mod.rs`, with `testutil::test_vault()`:
  - `mkdir` "a", then "a/b"; `readdir(root)` == `[a: Directory]`; `getattr("a/b").kind == Directory`.
  - The real directory for "a" holds `.cd-dir` (16 bytes) and one entry for "b". No real name holds clear text: assert that no real name contains `"a"` as a whole name.
  - `getattr` of a missing path gives `NotFound`. `mkdir` of an existing path gives `AlreadyExists`.
  - A long name: with `test_vault_with(64)`, `mkdir` of a 100-character name; the real root has a `.cd-cdl…` entry; `readdir` shows the clear name.
  - Foreign files: create `.DS_Store` and `garbage (1)` directly in the real root; `readdir(root)` does not show them.
  - **Review Focus 3:** open a second `CryptoFs` on the same vault directory (`open_with_master_key`), `mkdir` "x" through it. The first `CryptoFs` (which already listed the root) shows "x" on the next `readdir(root)`.
  - Two `.cd-dir` files: create "d" through fs, then a child "c" in it. Copy `.cd-dir` to `.cd-dir (conflicted copy)`, replace `.cd-dir` with new random bytes, and create "e" through fs. `readdir("d")` shows both "c" and "e".
  - `statfs().namelen == 255`.
  - An incomplete directory: create a real directory with a valid encrypted name but no `.cd-dir`. `getattr` gives `NotFound`, and the real directory is gone afterwards. With a foreign file inside it instead, `getattr` gives `InvalidFormat`.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core fs::`
Expected: FAIL.

- [ ] **Step 3: Implement** `path.rs`, `dirstate.rs`, `listing.rs`, and the `mkdir`/`getattr`/`statfs` parts of `dirs.rs` and `mod.rs`, as described above.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core fs::`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(core): add CryptoFs with path resolution, mkdir and readdir`.

---

### Task 11: Open files: OpenFile and the file API

**Files:**
- Create: `crates/crypto-drive-core/src/file.rs`, `crates/crypto-drive-core/src/fs/files.rs`

**Interfaces:**
- Consumes: `ChunkCipher`, `FileHeader`, size functions, `DirHandle`, `CryptoFs` internals.
- Produces:
  ```rust
  // file.rs
  pub struct OpenFile { /* file, cipher, plain_len, disk_len, chunks: BTreeMap<u64, Vec<u8>>, dirty: BTreeSet<u64> */ }
  impl OpenFile {
      pub const MAX_DIRTY_CHUNKS: usize = 64;
      pub fn create(file: std::fs::File, content_key: &[u8; 32]) -> Result<OpenFile>;  // writes 61-byte empty file
      pub fn open(file: std::fs::File, content_key: &[u8; 32]) -> Result<OpenFile>;
      pub fn len(&self) -> u64;
      pub fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>>;
      pub fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize>;
      pub fn truncate(&mut self, new_len: u64) -> Result<()>;
      pub fn flush(&mut self) -> Result<()>;
      pub fn sync(&mut self) -> Result<()>;   // flush + fsync
  }
  // CryptoFs (fs/files.rs)
  pub fn create(&self, path: &VPath, mode: u32) -> Result<(Attr, FileHandleId)>;
  pub fn open(&self, path: &VPath, write: bool, append: bool) -> Result<FileHandleId>;
  pub fn read(&self, fh: FileHandleId, offset: u64, size: u32) -> Result<Vec<u8>>;
  pub fn write(&self, fh: FileHandleId, offset: u64, data: &[u8]) -> Result<u32>;   // append => offset = len()
  pub fn flush(&self, fh: FileHandleId) -> Result<()>;
  pub fn fsync(&self, fh: FileHandleId) -> Result<()>;
  pub fn release(&self, fh: FileHandleId) -> Result<()>;   // flush, drop handle
  pub fn truncate(&self, path: &VPath, len: u64) -> Result<()>;
  pub fn flush_all(&self) -> Result<()>;                   // used at shutdown
  ```
- **OpenFile flush algorithm.** This is not fixed by the signatures, so follow it exactly:
  1. `old_last = chunk_count(disk_len) - 1` and `new_last = chunk_count(plain_len) - 1`.
  2. Reading chunk `i` from disk uses `is_last = (i == old_last)`. Chunks with `i > old_last` are not on disk; they are zeros.
  3. If `plain_len != disk_len`:
     - mark `new_last` dirty (load it first if it is on disk and not cached)
     - if `old_last < new_last`, also mark `old_last` and every index in `old_last+1..new_last` dirty
  4. Write every dirty chunk `i` at `chunk_offset(i)`, sealed with `is_last = (i == new_last)`. The plain length is `CHUNK_SIZE` for `i < new_last` (pad with zeros) and `plain_len - i*CHUNK_SIZE` for `i == new_last`.
  5. Then `set_len(ciphertext_size(plain_len))`, set `disk_len = plain_len`, clear `dirty`, and keep at most 8 clean chunks in the cache.
  6. `write` calls `flush` when `dirty.len() > MAX_DIRTY_CHUNKS`.
- **Shared state:**
  - `CryptoFs` keeps `open_files: Mutex<HashMap<(u64, u64) /*dev, ino*/, Weak<Mutex<OpenFile>>>>` and `handles: Mutex<HashMap<FileHandleId, Handle { file: Arc<Mutex<OpenFile>>, append: bool, write: bool }>>`.
  - `open` reuses a live `OpenFile` for the same `(dev, ino)`.
  - `getattr` uses `OpenFile::len()` when the file is open.
  - `truncate(path)` goes through the shared `OpenFile` when one exists, else opens a temporary one.
  - Writing through a read-only handle gives `NotPermitted`.
- **create:**
  - The name goes through `new_entry_name`. For a long name: `mkdir` the `.cd-cdl` entry, `write_atomic(".cd-name")`, then `create_file(".cd-content")`.
  - An existing name gives `AlreadyExists`.
  - Invalidate the parent.

- [ ] **Step 1: Write failing tests** in `file.rs`, on a temp file:

```rust
#[test] fn empty_file_is_61_bytes() { /* create => file len 61, len()==0, read(0,10) is empty */ }
#[test] fn write_read_across_chunks() {
    // write 200_000 bytes of pattern (i % 251) at 0; flush; reopen; read all => same; file len == ciphertext_size(200_000)
}
#[test] fn partial_overwrite_inside_chunk() { /* write 100 bytes at 65_530 over existing data; other bytes unchanged */ }
#[test] fn write_past_end_fills_zeros() { /* write b"x" at 150_000 on empty file => len 150_001, bytes 0..150_000 are 0 */ }
#[test] fn truncate_shrink_and_grow() {
    // 200_000 bytes -> truncate(70_000) -> reopen -> len 70_000, data prefix equal
    // -> truncate(140_000) -> bytes 70_000.. are 0
}
#[test] fn truncate_to_zero_is_61_bytes() {}
#[test] fn exact_chunk_multiple() { /* write 131_072 bytes => 2 chunks, reopen ok, file len 33 + 2*(65_536+28) */ }
#[test] fn dirty_limit_triggers_flush() { /* write 70 chunks without flush; real file len already > 61 */ }
```

  In `fs/files.rs`:
  - `create` "f.txt", `write` "hello", `release`, `open`, `read` == "hello"; `getattr.size == 5`.
  - Two handles on the same file share state: write via h1 without flush, then read via h2 sees the data.
  - Append: `open(write, append)`, `write` at offset 0 appends.
  - `write` on a read-only handle gives `NotPermitted`.
  - A long file name (`test_vault_with(64)`, 120 characters) round trip.
  - `create` of an existing name gives `AlreadyExists`.
  - `getattr` while dirty shows the in-memory size.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core file`
Expected: FAIL.

- [ ] **Step 3: Implement** `file.rs` and `fs/files.rs` as described above.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core file`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(core): add random access encrypted files`.

---

### Task 12: unlink, rmdir, set_times, set_mode

**Files:**
- Modify: `crates/crypto-drive-core/src/fs/dirs.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn unlink(&self, path: &VPath) -> Result<()>;   // directory => IsADirectory
  pub fn rmdir(&self, path: &VPath) -> Result<()>;    // file => NotADirectory; root => InvalidArgument
  pub fn set_times(&self, path: &VPath, atime: Option<SystemTime>, mtime: Option<SystemTime>) -> Result<()>;
  pub fn set_mode(&self, path: &VPath, mode: u32) -> Result<()>;
  ```
- **rmdir:** list the real directory. If any entry exists other than `.cd-dir`, `.cd-dir.tmp`, the extra `.cd-dir*` copies and `.cd-name`, give `NotEmpty`. Otherwise unlink those control files (`.cd-dir` last), then `rmdir` the directory (or the long entry).
- **unlink of a long file:** unlink `.cd-content`, then `.cd-name`, then `rmdir` the entry.
- For long entries, `set_times` and `set_mode` act on `.cd-content` (file) or on the entry directory (directory).
- Invalidate the parent (and the path itself for rmdir).

- [ ] **Step 1: Write failing tests**
  - Create, then unlink: `getattr` gives `NotFound`, and the real directory is empty.
  - `rmdir` of a non-empty directory gives `NotEmpty`. `rmdir` of an empty directory leaves no real entry.
  - A foreign file `.DS_Store` placed into the real directory makes `rmdir` give `NotEmpty`.
  - `unlink` of a directory gives `IsADirectory`. `rmdir` of a file gives `NotADirectory`.
  - Long name unlink and rmdir leave nothing behind.
  - `set_mode(0o600)` is seen in `getattr.mode & 0o777`. `set_times` mtime is seen in `getattr`.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core fs::dirs`
Expected: FAIL.

- [ ] **Step 3: Implement** as described above.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core fs::dirs`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(core): add unlink, rmdir and attribute changes`.

---

### Task 13: rename

**Files:**
- Create: `crates/crypto-drive-core/src/fs/rename.rs`

**Interfaces:**
- Produces: `pub fn rename(&self, from: &VPath, to: &VPath) -> Result<()>`.
- **Rules** (spec §5.5):
  - `from == to` does nothing.
  - `to` inside `from` (a directory moved into itself) gives `InvalidArgument`.
  - An existing target file is replaced. An existing empty target directory is removed first (like rmdir). A non-empty target gives `NotEmpty`. Directory over file gives `NotADirectory`. File over directory gives `IsADirectory`.
  - The new name is always encrypted with the target parent's canonical `dir_id`. This also clears conflict names.
- **Step order per layout change.** Each order keeps data safe after a crash:
  - short → short: `rename(real_from, to_dir, real_to)`.
  - short file → long: `mkdir(entry)`, `write_atomic(.cd-name)`, `rename(real_from → entry/.cd-content)`.
  - short dir → long: `rename(real_from → entry)`, then `write_atomic(entry/.cd-name)`.
  - long file → short: `rename(entry/.cd-content → real_to)`, unlink `.cd-name`, `rmdir(entry)`.
  - long dir → short: `rename(entry → real_to)`, then unlink `real_to/.cd-name`.
  - long → long: `rename(entry → new_entry)`, then `write_atomic(new_entry/.cd-name)`.
- Afterwards: invalidate both parents and the whole `from` subtree. Open files stay valid, because they are keyed by `(dev, ino)`.

- [ ] **Step 1: Write failing tests** (use `test_vault_with(64)` where long names are needed):
  - Rename a file in the same directory: the content is kept, and the old name gives `NotFound`.
  - Move a file into another directory: the content is kept, and the real name differs from a name encrypted under the old `dir_id`.
  - Move a directory with children: the children are readable at the new path, and it was a single real rename (the inode of the real directory is unchanged).
  - All 6 layout changes (short/long × file/dir), each followed by `readdir` and a content check.
  - Replace an existing file: the target has the new content.
  - A non-empty target directory gives `NotEmpty`. Moving a directory into its own child gives `InvalidArgument`.
  - A file that is open during the rename can still be read and written through its handle afterwards.
  - Conflict copy: make the real copy `<enc> (1)` of "a.txt"; `readdir` shows `a (conflict 1).txt`; rename it to "b.txt"; `readdir` shows "a.txt" and "b.txt".

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-core rename`
Expected: FAIL.

- [ ] **Step 3: Implement** as described above.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive-core rename`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(core): add rename for all name layouts`.

---

### Task 14: Integrity check, tamper tests, golden vault, model tests

**Files:**
- Create: `crates/crypto-drive-core/src/check.rs`
- Create: `crates/crypto-drive-core/tests/{tamper.rs,golden.rs,model.rs}`, `crates/crypto-drive-core/tests/golden/v1/` (generated)

**Interfaces:**
- Consumes: everything above.
- Produces:
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)] pub enum Severity { Warning, Error }
  #[derive(Clone, Debug, PartialEq, Eq)] pub enum FindingKind {
      MissingDirId, MultipleDirIds, IncompleteLongEntry, ConflictCopy, ForeignEntry,
      UndecryptableName, InvalidFileSize, HeaderInvalid, ChunkAuthFailed { index: u64 }, LongNameMismatch }
  #[derive(Clone, Debug)] pub struct Finding { pub severity: Severity, pub real_path: PathBuf, pub kind: FindingKind }
  pub fn check_vault(vault: &UnlockedVault) -> Result<Vec<Finding>>;
  pub fn exit_code(findings: &[Finding]) -> i32;   // 0 none, 1 only warnings, 2 any error
  ```
- `ConflictCopy`, `ForeignEntry` and `MultipleDirIds` are warnings. Everything else is an error. `real_path` is relative to the vault root, so it never contains clear names.

- [ ] **Step 1: Write failing tests in `check.rs`**
  - A clean vault (files, directories, long names) gives no findings and exit code 0.
  - Each case below is built in the real directory and gives the matching finding and exit code:
    - a foreign `.DS_Store` gives `ForeignEntry` and exit 1
    - a conflict copy gives `ConflictCopy`
    - a second `.cd-dir` copy gives `MultipleDirIds`
    - a directory without `.cd-dir` but with entries gives `MissingDirId` and exit 2
    - a `.cd-cdl` entry without `.cd-name` gives `IncompleteLongEntry`
    - a `.cd-name` whose hash does not match the entry name gives `LongNameMismatch`
    - a file of 40 bytes gives `InvalidFileSize`
    - a bit flip in chunk 2 gives `ChunkAuthFailed { index: 2 }`
    - a renamed real file `AAAAAAAAAAAAAAAAAAAAAAAA` gives `UndecryptableName`

- [ ] **Step 2: Write `tests/tamper.rs`** (spec §9). Every case must produce an `Err` on read or unlock, never other bytes:
  - one bit flipped in the header, in each of 3 chunks, in a real name, in `.cd-dir`, in `.cd-vault` and in `.cd-key`
  - chunks 0 and 1 swapped
  - a file cut to `33 + 65_564` bytes, and a file cut to 33 bytes
  - a real file moved into another real directory (it must not appear, or it must fail on read)
  - the contents of two files with the same size swapped
  - a wrong key file
  - changed Argon2 parameters

- [ ] **Step 3: Write `tests/golden.rs`**
  - `#[test] #[ignore] fn generate_golden_v1()` writes `tests/golden/v1/vault/` and `tests/golden/v1/key` with password `golden-password`, `Argon2Params::MIN` and `max_name_length` 220. Contents:
    - `hello.txt` = `"Hello, crypto-drive!\n"`
    - `empty.bin` = empty
    - `docs/big.bin` = 200_000 bytes of `(i % 251) as u8`
    - `docs/` + `"long-name-" + "x" * 200 + ".txt"` = `"long\n"`
    - an empty directory `empty-dir/`
  - `#[test] fn golden_v1_is_readable()` unlocks, then checks every file, the `readdir` results and that `check_vault` gives no findings.
  - Run the generator once: `cargo test -p crypto-drive-core --test golden -- --ignored generate_golden_v1`. Commit the generated files. Never regenerate them in later work.

- [ ] **Step 4: Write `tests/model.rs`** with `proptest` (64 cases, at most 40 operations each)
  - Operations: `Write { file: 0..4, offset: 0..300_000, len: 0..70_000 }`, `Read`, `Truncate { len: 0..300_000 }`, `Mkdir { dir: 0..3 }`, `Rename { from, to }`, `Unlink`, `Rmdir`, `Reopen`. `Reopen` drops `CryptoFs`, opens it again with `open_with_master_key` and then goes on.
  - The model is `BTreeMap<String, Vec<u8>>` plus a set of directories. Each operation must give the same `Ok`/`Err` kind and the same bytes in both.
  - Names are drawn from a fixed list with Unicode and one 150-character name. The vault uses `max_name_length` 64.

- [ ] **Step 5: Run everything and verify it passes**

Run: `cargo test -p crypto-drive-core`
Expected: all pass. The golden test passes against the committed files.

- [ ] **Step 6: Commit** with message `test(core): add check, tamper, golden and model tests`.

---

### Task 15: CLI: password input, init, passwd, recovery-key, recover, check, hardening

**Files:**
- Create: `crates/crypto-drive/src/{password.rs,hardening.rs,cmd/mod.rs,cmd/init.rs,cmd/passwd.rs,cmd/recovery.rs,cmd/recover.rs,cmd/check.rs}`, `crates/crypto-drive/tests/cli.rs`
- Modify: `crates/crypto-drive/src/main.rs`

**Interfaces:**
- Consumes: core `init_vault`, `unlock_vault`, `open_with_master_key`, `KeyFile`, `key_file_path`, `encode_recovery_key`, `decode_recovery_key`, `check_vault`, `exit_code`, `Argon2Params`, `secret::mlock_failed`.
- Produces:
  ```rust
  // password.rs
  pub struct PasswordArgs { pub fd: Option<i32>, pub env_var: &'static str }   // "CRYPTO_DRIVE_PASSWORD" / "CRYPTO_DRIVE_NEW_PASSWORD"
  pub fn read_password(args: &PasswordArgs, prompt: &str) -> Result<secrecy::SecretString, CliError>;
  pub fn read_new_password(args: &PasswordArgs) -> Result<SecretString, CliError>;   // TTY: ask twice, must match
  pub fn read_recovery_key(fd: Option<i32>) -> Result<SecretString, CliError>;
  pub fn strip_one_newline(s: &mut String);    // removes one trailing "\n" or "\r\n"
  // hardening.rs
  pub fn disable_core_dumps();                 // setrlimit(RLIMIT_CORE, 0), warn on error
  // main.rs
  #[derive(Debug, thiserror::Error)] pub enum CliError { #[error(transparent)] Core(#[from] crypto_drive_core::Error),
      #[error("{0}")] Usage(String), #[error(transparent)] Io(#[from] std::io::Error) }
  // exit codes: 0 ok, 1 check warnings, 2 check errors or any CliError
  ```
- **clap:** subcommands and flags exactly as in spec §7. The shared flags are `--key-file`, `--password-fd`, `--new-password-fd`, `--argon2-memory`, `--argon2-iterations`, `--argon2-parallelism`, `--max-name-length`, `--recovery-key-fd` and `--overwrite`. `mount`/`unmount` are added in Task 18. Until then they print "not implemented yet" and exit 2.
- **Password source order:** `--password-fd`, then the env var (prints `warning: reading the password from CRYPTO_DRIVE_PASSWORD; other processes of the same user may see it` on stderr), then the TTY (`rpassword::prompt_password`). If none is available: `Usage("no password source: use a TTY, --password-fd or CRYPTO_DRIVE_PASSWORD")`. An empty password gives `Usage("the password must not be empty")`. The fd source is read until EOF and `strip_one_newline` is applied.
- **Output:**
  - `init` and `recovery-key` print exactly one line `RECOVERY KEY: <key>` on stdout.
  - On stderr they print `Write this recovery key down and keep it offline. Anyone with it can open the vault.`
  - Argon2 parameters below the default print `warning: Argon2 parameters are below the recommended defaults`.
  - `mlock_failed()` prints `warning: could not lock key memory; keys may be swapped to disk`.
- **check** prints one line per finding: `<warning|error>: <real_path>: <kind>`. It exits with `exit_code`.
- **recover** without `--overwrite` on an existing key file gives `Usage("key file exists; use --overwrite to replace it")`.
- `main` calls `disable_core_dumps()` first.

- [ ] **Step 1: Write failing unit tests in `password.rs`**
  - `strip_one_newline`: `"pw\n"` → `"pw"`, `"pw\r\n"` → `"pw"`, `"pw\n\n"` → `"pw\n"`, `"pw"` → `"pw"`.
  - **Review Focus 5:** `read_password` with a pipe fd that contains `"secret\n"` returns `"secret"`. Use `nix::unistd::pipe`, write, close the write end, and pass the read end's raw fd.

- [ ] **Step 2: Write failing CLI tests in `tests/cli.rs`.** Run the built binary with `std::process::Command` and `env!("CARGO_BIN_EXE_crypto-drive")`. Send passwords through `--password-fd 0` and `--new-password-fd 0` with stdin piped. Always pass `--argon2-memory 19456 --argon2-iterations 2 --argon2-parallelism 1`. Tests:
  - `init` creates `.cd-vault` and `.cd-key`. stdout matches `^RECOVERY KEY: [0-9A-Z]{5}(-[0-9A-Z]{5}){10}\n$`.
  - `init` with `--key-file <other dir>/k`: the vault has no `.cd-key`, and `check` with `--key-file` exits 0.
  - `init` into a non-empty directory exits 2 with a message on stderr.
  - `passwd` (the old password comes from `--password-fd 3`): use `std::os::unix::process::CommandExt::pre_exec` to dup a pipe to fd 3, and send the new one on fd 0. After that, `check` with the old password exits 2 with `wrong password or damaged key file`, and with the new one it exits 0.
  - `recovery-key` prints the same key as `init`.
  - `recover --overwrite --recovery-key-fd 3` with the key from `init` and a new password: then `check` with the new password exits 0. Without `--overwrite` it exits 2.
  - `check` on a vault with a foreign `.DS_Store` exits 1.
  - `CRYPTO_DRIVE_PASSWORD` works and prints the warning on stderr.

- [ ] **Step 3: Run them and verify they fail**

Run: `cargo test -p crypto-drive`
Expected: FAIL.

- [ ] **Step 4: Implement** `password.rs`, `hardening.rs`, the commands and `main.rs`.

- [ ] **Step 5: Run the tests and verify they pass**

Run: `cargo test -p crypto-drive`
Expected: all pass.

- [ ] **Step 6: Commit** with message `feat(cli): add init, passwd, recovery-key, recover and check`.

---

### Task 16: FUSE adapter

**Files:**
- Create: `crates/crypto-drive-fuse/src/{inodes.rs,errno.rs,adapter.rs}`
- Modify: `crates/crypto-drive-fuse/src/lib.rs`

**Interfaces:**
- Consumes: `CryptoFs` and all its methods, `VPath`, `Attr`, `FileKind`, `DirEntry`, `FileHandleId`, `Error`.
- Produces:
  ```rust
  // inodes.rs
  pub const ROOT_INO: u64 = 1;
  pub struct InodeTable { /* by_ino: HashMap<u64, Node { path: VPath, lookups: u64 }>, by_path: HashMap<VPath, u64>, next: u64 */ }
  impl InodeTable {
      pub fn new() -> Self;                                   // root = 1
      pub fn lookup(&mut self, path: &VPath) -> u64;          // insert or reuse; lookups += 1
      pub fn path(&self, ino: u64) -> Option<VPath>;
      pub fn forget(&mut self, ino: u64, n: u64);             // remove at 0 (never the root)
      pub fn rename(&mut self, from: &VPath, to: &VPath);     // moves the subtree; drops an old entry at `to`
      pub fn remove_path(&mut self, path: &VPath);
  }
  // errno.rs
  pub fn to_errno(e: &crypto_drive_core::Error) -> i32;      // table in spec §8; Io(e) => raw_os_error or EIO
  // adapter.rs
  pub struct FuseFs { fs: Arc<CryptoFs>, inodes: Mutex<InodeTable>, uid: u32, gid: u32, on_destroy: Option<std::sync::mpsc::Sender<()>> }
  impl FuseFs { pub fn new(fs: Arc<CryptoFs>, on_destroy: Option<Sender<()>>) -> Self; }
  impl fuser::Filesystem for FuseFs { /* fuser 0.18: methods take &self */ }
  pub fn name_to_str(name: &std::ffi::OsStr) -> Result<&str, i32>;   // not UTF-8 => EINVAL
  pub fn to_file_attr(ino: u64, a: &Attr) -> fuser::FileAttr;        // blocks = ceil(size/512), blksize 4096, perm = mode & 0o7777
  ```
- **Implemented methods:** `init`, `destroy` (calls `fs.flush_all()`, sends on `on_destroy`), `lookup`, `forget`, `getattr`, `setattr`, `mkdir`, `unlink`, `rmdir`, `rename`, `open`, `create`, `read`, `write`, `flush`, `release`, `fsync`, `opendir`, `readdir`, `releasedir`, `statfs`.
  - `setattr`: size → `truncate`, mode → `set_mode`, times → `set_times` (handle `TimeOrNow::Now`). Any uid/gid change gives `EPERM`.
  - `open`/`create`: write = `O_WRONLY|O_RDWR`, append = `O_APPEND`. `O_TRUNC` calls `truncate(path, 0)` after open.
  - `rename`: a non-zero `flags` gives `EINVAL`.
  - Every other method, including xattrs, `symlink`, `link` and `mknod`, uses the fuser defaults or returns `ENOTSUP`/`EPERM` as in spec §6.
  - TTL is 1 second, generation 0.
  - `AuthFailed` and `InvalidFormat` are logged with `log::warn!` and the real path (`what`). Clear names are only logged at `debug` level.
  - `readdir` emits `.` and `..` first, then the entries. It honours `offset` (index + 1).
- `lib.rs` re-exports `FuseFs`, `InodeTable` and `to_errno`.

- [ ] **Step 1: Write failing unit tests**
  - `InodeTable`: root is 1; `lookup` twice gives the same ino; `forget` removes it at zero lookups; `forget` on the root keeps it; `rename` of "a" to "b" moves "a/x" to "b/x"; `rename` onto an existing path drops the old inode for that path.
  - `to_errno`: one assertion per row of the spec §8 table, for example `to_errno(&Error::AuthFailed{what: "x".into()}) == libc::EIO`.
  - `to_file_attr`: size 1000 → blocks 2, kind maps, perm 0o644.
  - **Review Focus 4:** `name_to_str(OsStr::from_bytes(b"\xff\xfe"))` gives `Err(libc::EINVAL)`.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive-fuse`
Expected: FAIL.

- [ ] **Step 3: Implement** `inodes.rs`, `errno.rs` and `adapter.rs`. Check every method signature against docs.rs for `fuser` 0.18.0 (methods take `&self`; the types are `INodeNo`, `FileHandle`, `OpenFlags`).

- [ ] **Step 4: Run the tests and the build**

Run: `cargo test -p crypto-drive-fuse && cargo build --workspace`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(fuse): add fuser adapter with inode table and errno mapping`.

---

### Task 17: Mount, unmount and mount tests

**Files:**
- Create: `crates/crypto-drive-fuse/src/mount.rs`, `crates/crypto-drive-fuse/tests/mount.rs`

**Interfaces:**
- Consumes: `FuseFs`, `CryptoFs`.
- Produces:
  ```rust
  pub struct MountRequest { pub mountpoint: PathBuf, pub volume_name: String, pub extra_options: Vec<String> }
  pub fn mount_options(req: &MountRequest) -> Vec<fuser::MountOption>;
      // FSName("crypto-drive"), DefaultPermissions, macOS: CUSTOM("noappledouble"), CUSTOM("volname=<name>"), then CUSTOM(each extra)
  pub enum StopReason { Signal, Unmounted }
  pub fn mount_and_wait(fs: Arc<CryptoFs>, req: &MountRequest, ready: impl FnOnce()) -> Result<StopReason, std::io::Error>;
      // block SIGINT/SIGTERM in this thread before spawning (threads inherit the mask);
      // spawn_mount(FuseFs, mountpoint, &config with n_threads = Some(4)); call ready();
      // start a thread that waits with SigSet::wait and sends Signal on a channel; destroy sends Unmounted;
      // on Signal: drop the BackgroundSession (unmounts); then fs.flush_all()
  pub fn unmount_command(mountpoint: &Path, force: bool) -> std::process::Command;
      // macOS: umount [-f] <mp>; Linux: fusermount3 -u [-z] <mp>
  ```

- [ ] **Step 1: Write failing tests**
  - `mount_options` on Linux contains `FSName("crypto-drive")` and `DefaultPermissions` and no `noappledouble`. Use `#[cfg]` to also check the macOS variant on macOS.
  - `unmount_command` gives the program and args per OS (`fusermount3`, `["-u", mp]`; with force `["-u", "-z", mp]`).

- [ ] **Step 2: Write the `#[ignore]` mount tests** in `tests/mount.rs`. Each one creates a test vault, mounts it to a temp directory in a background thread and works through `std::fs` on the mountpoint:
  - write and read back 5 MiB, `rename`, `create_dir_all("a/b/c")`, `remove_dir_all`, `read_dir`
  - `set_len` grow and shrink, `OpenOptions::append`
  - unmount with `unmount_command` and check `StopReason::Unmounted`

- [ ] **Step 3: Implement** `mount.rs`.

- [ ] **Step 4: Run**

Run: `cargo test -p crypto-drive-fuse`
Expected: all pass. The mount tests show as ignored. On the macOS host, also run `cargo test -p crypto-drive-fuse -- --ignored`. It is expected to pass there; the owner runs it.

- [ ] **Step 5: Commit** with message `feat(fuse): add mount loop and unmount command`.

---

### Task 18: CLI mount, unmount and daemon

**Files:**
- Create: `crates/crypto-drive/src/cmd/{mount.rs,unmount.rs}`
- Modify: `crates/crypto-drive/src/main.rs`, `crates/crypto-drive/tests/cli.rs`

**Interfaces:**
- Consumes: `unlock_vault`, `lock_vault`, `CryptoFs::new`, `MountRequest`, `mount_and_wait`, `unmount_command`, `read_password`.
- Produces:
  ```rust
  pub fn validate_mount_paths(vault_dir: &Path, mountpoint: &Path) -> Result<(), CliError>;
      // both canonicalized; mountpoint must exist, be a directory and be empty;
      // error if mountpoint is inside vault or vault is inside mountpoint or they are equal:
      // Usage("the mount point must not be inside the vault, and the vault must not be inside the mount point")
  ```
- **mount flow:**
  1. `validate_mount_paths`.
  2. If `--daemon`: `fork` first (before any thread). The parent reads one status line from a pipe: `"ok\n"` means exit 0; `"err <message>\n"` means print it and exit 2; EOF means exit 2.
  3. The child (or the foreground process) does `read_password`, `lock_vault`, `unlock_vault`, `CryptoFs::new` and `mount_and_wait`.
  4. The `ready` callback: in daemon mode it writes `"ok\n"`, closes the pipe, calls `setsid` and reopens stdin/stdout/stderr to `/dev/null`. In the foreground it prints `Mounted <vault> at <mountpoint>. Press Ctrl+C to unmount.` on stderr.
  5. A failure before `ready` sends `"err <message>\n"` in daemon mode.
- `-o OPT` (repeatable) goes into `extra_options`. `--debug` sets the `env_logger` level to `debug` and prints `warning: debug logging shows clear file names`. Otherwise the level is `warn`.
- **unmount:** run `unmount_command`. On a non-zero exit, print its stderr. If the stderr contains "busy", print `the drive is busy; close open files or use --force`. Exit 2.

- [ ] **Step 1: Write failing tests**
  - **Review Focus 1:** unit tests for `validate_mount_paths`: mountpoint inside the vault fails; vault inside the mountpoint fails; the same path fails; a non-empty mountpoint fails; separate empty directories are ok.
  - CLI test: `mount` with a mountpoint inside the vault exits 2 with that message, and the password is never asked (no stdin is given).
  - CLI test: `mount` with a wrong password exits 2 with `wrong password or damaged key file`. In the container, FUSE is never reached.

- [ ] **Step 2: Run them and verify they fail**

Run: `cargo test -p crypto-drive`
Expected: FAIL.

- [ ] **Step 3: Implement** `cmd/mount.rs` and `cmd/unmount.rs` with `nix::unistd::{fork, setsid, pipe}`.

- [ ] **Step 4: Run the tests and verify they pass**

Run: `cargo test --workspace`
Expected: all pass.

- [ ] **Step 5: Commit** with message `feat(cli): add mount, unmount and daemon mode`.

---

### Task 19: Docs, smoke test and benchmarks

**Files:**
- Create: `README.md`, `docs/format.md`, `scripts/smoke-test.sh`, `crates/crypto-drive-core/benches/throughput.rs`
- Modify: `crates/crypto-drive-core/Cargo.toml` (`[[bench]] name = "throughput" harness = false`)

**Interfaces:**
- Consumes: the CLI and the core API.

- [ ] **Step 1: Write `docs/format.md`.** It is spec §4 in normative form (MUST/MUST NOT), with the layouts of every file. Add a section "Test vectors" that points to `crates/crypto-drive-core/tests/golden/v1/`.

- [ ] **Step 2: Write `README.md`** in simple English. Sections:
  - What it is
  - Install: Rust 1.99.1; macOS: `brew install --cask macfuse` and `brew install pkgconf`, plus how to allow the kernel extension, or `-o backend=fskit` on macOS 26; Linux: `fuse3`
  - Quick start: `init`, `mount`, `unmount`
  - Key file and `--key-file`
  - Recovery key
  - Sync clients and conflict copies
  - Threat model and what stays visible (copy from spec §2)
  - Limits of the MVP (spec §1.3)
  - License: AGPL-3.0-or-later

- [ ] **Step 3: Write `scripts/smoke-test.sh`** (with the license header). It uses `set -euo pipefail`, makes a temp vault and mountpoint, and runs `init` with a password from fd. Then:
  - `mount --daemon`
  - create 100 small files and 1 file of 300 MiB from `/dev/urandom`
  - `mkdir -p` a deep tree with a 200-character name
  - rename a directory
  - `rsync -a` a source tree in and out, then `diff -r`
  - compare `shasum -a 256` before and after
  - `unmount`, mount again, and verify again
  - `crypto-drive check` exits 0
  - Every step prints `OK <step>`. It exits non-zero on the first failure.

- [ ] **Step 4: Write `benches/throughput.rs`** with criterion groups:
  - `chunk_seal_open` (64 KiB)
  - `name_encrypt_decrypt` (30-character name)
  - `fs_sequential_write_read_16MiB`
  - `fs_random_4k_writes`, using a test vault from `testutil`

- [ ] **Step 5: Verify**

Run: `bash -n scripts/smoke-test.sh && cargo bench -p crypto-drive-core -- --quick && scripts/check-license-headers.sh && cargo deny check`
Expected: all pass. Record the benchmark numbers in the final summary.

- [ ] **Step 6: Commit** with message `docs: add README, format spec, smoke test and benchmarks`.

---

### Task 20: Final verification

- [ ] **Step 1: Run every check**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace && cargo deny check && scripts/check-license-headers.sh`
Expected: everything passes.

- [ ] **Step 2: Give the owner the macOS steps.** These run on the host:
  - `brew install --cask macfuse && brew install pkgconf`
  - `cargo build --release`
  - `cargo test --workspace -- --include-ignored`
  - `scripts/smoke-test.sh`
  - optional: `-o backend=fskit` on macOS 26
