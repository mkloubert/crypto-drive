# crypto-drive – Format hardening (entry binding, size padding, key rotation, fuzzing)

- **Date:** 2026-10-31
- **Status:** Draft for review
- **Builds on:** `docs/superpowers/specs/2026-10-31-crypto-drive-design.md` (the "base spec")
- **Author:** Marcel Joachim Kloubert

## 1. Goal

Make the on-disk format final before the first release:

1. **Entry binding:** detect when the encrypted content of one file (or one directory) is put under the name of another one.
2. **Size padding (optional):** hide exact file sizes when the owner turns it on at `init`.
3. **Master key rotation:** a command that re-encrypts the whole vault with a new master key, so old key files, old passwords and old recovery keys stop working.
4. **Rollback:** stays undetected; this is now documented clearly.
5. **Fuzzing:** coverage-guided fuzz tests for every parser and for hostile vault trees, so that untrusted cloud data can never crash, hang or exhaust the program (section 14).

### 1.1 Decisions (from the owner)

| Topic | Decision |
|---|---|
| Existing vaults | None with real data. **Format v1 is replaced in place.** No migration, no v1-old reader. The golden vault and the test vectors are made again. |
| Entry binding | A random entry id is encrypted together with the name and bound into the content (section 3). |
| Rotation | **Offline command** `crypto-drive rotate-key`, resumable after a crash. No rotation while mounted. |
| Rollback | **Only documented.** No detection, no write counter. |
| Size padding | **Optional per vault**, chosen at `init` with `--pad-sizes`, cannot be changed later. |
| Fuzzing | Part of this spec; runs against the final format (section 14). |

### 1.2 Not in scope

- Rotation while the drive is mounted, or lazy re-encryption on access.
- Rollback detection of any kind.
- Turning padding on or off after `init`.
- Reading vaults written by earlier development builds.
- Running the fuzzers in a CI service (there is no CI yet; scripts make local runs easy).

### 1.3 Constraints that stay

Everything in the base spec stays unless this spec says otherwise: per-file encryption, no central metadata file that changes during normal use, cheap rename and move, conflict-copy handling, macOS and Linux, simple English, AGPL header.

## 2. Key epochs and key hierarchy (replaces base spec §4.2)

Every master key belongs to a **key epoch**, a `u32` that starts at 1 at `init` and grows by 1 with each rotation.

```
password ──Argon2id(salt, m, t, p)──► KEK (32 B)
KEK ──AES-256-GCM unwrap──► key set = { (epoch, MK_epoch), … }   (1 or 2 entries)

For each epoch e in the key set:
PRK_e        = HKDF-SHA-512-Extract(salt = vault_id ‖ e (u32, little endian), ikm = MK_e)
K_names[e]   = HKDF-Expand(PRK_e, "crypto-drive v1 names",   64)   # AES-256-SIV
K_content[e] = HKDF-Expand(PRK_e, "crypto-drive v1 content", 32)
K_check[e]   = HKDF-Expand(PRK_e, "crypto-drive v1 check",   32)   # HMAC-SHA-256

K_file       = HKDF-SHA-512(salt = file_nonce, ikm = K_content[file_epoch],
                            info = "crypto-drive v1 file" ‖ file_id, 32)
K_size       = HKDF-SHA-512(salt = file_nonce, ikm = K_content[file_epoch],
                            info = "crypto-drive v1 size" ‖ file_id, 32)   # padded vaults only
```

- The **write epoch** is the highest epoch in the key set. New names and new files always use it.
- Outside a rotation the key set has exactly one entry.

## 3. Entry binding

Every entry has a 16-byte **entry id**:

- a file: a random `file_id`, made when the file is created, stored in the file header (section 5);
- a directory: its `dir_id` from `.cd-dir` (base spec §4.5, unchanged).

### 3.1 Names (replaces base spec §4.6 formula)

```
enc  = AES-256-SIV(K_names[e], AD = [parent_dir_id], entry_id ‖ NFC(clear_name))
name = B64(enc)
```

- The root's children use `parent_dir_id = vault_id` (as before).
- Decrypting gives `entry_id` (the first 16 bytes) and the clear name (the rest). Fewer than 17 plaintext bytes → `AuthFailed`.
- **Which epoch:** a real name carries no epoch. The reader tries `K_names[e]` for every epoch in the key set, highest first.
- Overflow rule, `.cd-name`, NFC, invalid names, the 1024-byte clear name limit and case rules stay as in base spec §4.6. The maximum length of a `.cd-name` grows by 22 characters (the encoded entry id).
- Names are about 22 characters longer than before, so a name goes to an overflow entry from about 135 clear bytes on (default `max_name_length` 220).

### 3.2 Binding checks

- **File:** after a name decrypts to `(file_id, name)`, the file header's `file_id` must be the same. Otherwise → `AuthFailed`. The header's `file_id` cannot be changed unnoticed, because it is part of `K_file` (any change makes every chunk fail).
- **Directory:** after a name decrypts to `(dir_id, name)`, the directory's canonical `.cd-dir` must hold the same `dir_id`. Otherwise → `AuthFailed`. (Extra `.cd-dir` conflict copies stay readable for children, base spec §5.3, but the canonical one decides the binding.)
- **Rename and move** encrypt the name again with the same entry id. Content and `.cd-dir` are not touched. Cost stays O(1).
- **Copy inside the drive** creates a new file and so a new `file_id`.
- **Conflict copies** from sync clients keep working: name and content come from the same real entry.

What this detects: one file's content under another file's name (in any directory), and one directory's subtree under another directory's name. What it does not detect: rollback (section 8).

### 3.3 Name index (lookup without deterministic names)

Because a real name now contains the random entry id, the real name of a clear name cannot be computed any more; base spec §5.2 "encrypt the name and stat it" no longer works. Instead:

- Every cached directory state (base spec §5.2 cache) holds a **name index**: clear display name → `(real name, layout, entry id, epoch)`. It is the listing of base spec §5.3 (including conflict copies, foreign entries skipped) with the entry id and epoch added.
- The index is built the first time the directory is needed: list the real directory and decrypt every name, O(n) once (about 1 µs per name).
- **Every lookup uses the index only.** There is no probing by encrypting a name.
- **Own changes update the index in place** instead of dropping it: create and mkdir insert, unlink and rmdir remove, rename removes from the source index and inserts into the target index. After the change the stored mtime of the real directory is read again, so the own change does not count as an outside change.
- **Outside changes** (a sync client) change the real directory's mtime; the next access sees the different mtime and builds the index again (as base spec §5.2 already does).
- **Limit (documented):** an outside change in the same directory that lands within the same mtime tick as an own change can stay unseen until the next change in that directory. File systems with coarse mtimes (FAT: 2 s) make this more likely.
- **Second limit (documented):** outside edits that do not change the mtime of the parent directory are also not seen by a running drive until the parent directory changes. Examples: a change inside an overflow entry, or a `chmod` of an entry.
- **Unreadable entries:** an unreadable long-name entry is hidden from listings and blocks creating other names that would also need a long entry in that directory. An unreadable short entry blocks only its own name.
- Memory: about the length of the name plus 64 bytes per entry; the directory cache keeps at most 1024 directories (base spec).
- The quadratic-create guard of the base implementation (no listing on a plain miss) is replaced by this index; a test asserts that creating N files in one directory builds the index once.


## 4. Vault marker `.cd-vault` (replaces base spec §4.4), 66 bytes

```
offset  length  field
0       8       magic = "CD-VAULT"
8       2       format_version = 1
10      2       max_name_length (64 … 255, default 220)
12      2       flags: bit 0 = pad_sizes; all other bits MUST be 0
14      16      vault_id (random)
30      4       epoch (u32) = the vault's current epoch
34      32      tag = HMAC-SHA-256(K_check[epoch], bytes 0–33)
```

- Unknown flag bits → `InvalidFormat { what: ".cd-vault flags" }` before any key work; nothing is written.
- **Unlock** verifies the tag with `K_check[epoch]` taken from the key set. If the key set has no key for this epoch → `WrongKey`.
- The marker is written by `init` and by the last step of `rotate-key` only (atomic: temporary file, `fsync`, `rename`, `fsync` of the directory). It is no longer "never changed", but it changes only on rotation.

## 5. File content (replaces base spec §4.7)

```
header, not padded (53 B):
  version (1 B) = 1 ‖ epoch (u32) ‖ file_nonce (32 B, random) ‖ file_id (16 B, random)

header, padded vault (89 B):
  the 53 bytes above ‖ size block (36 B)
  size block = nonce (12 B, random) ‖ AES-256-GCM(K_size, nonce, plain_len (u64), AD = header bytes 0–52) ‖ tag (16 B)

chunks:   chunk_0 ‖ … ‖ chunk_{n-1}     (exactly as base spec §4.7, keyed with K_file)
padding:  random bytes (padded vault only)
```

- `H` = header length (53 or 89). An empty file has `H + 28` bytes before padding.
- The chunk rules (size `S = 65536`, `is_last`, AD, fresh random nonce per write) are unchanged.
- The header's `epoch` is part of the HKDF salt chain (through `K_content[epoch]`) and of the size block AD, so it cannot be changed unnoticed either.

### 5.1 Not padded

Clear size from the ciphertext size `C` as before, with 53 instead of 33:
`n = ceil((C − 53) / (S + 28))`, clear size `= C − 53 − 28·n`. Invalid: `C < 81`, a last chunk with fewer than 29 bytes when n > 1, unknown `version`.

### 5.2 Padded (`pad_sizes` flag)

- `L = 89 + ciphertext_size_of_chunks(plain_len)` is the unpadded length.
- The real file length MUST be `stage(L)`:

  | `L` | `stage(L)` |
  |---|---|
  | ≤ 4096 | 4096 |
  | ≤ 1 MiB (1048576) | next power of two ≥ `L` |
  | > 1 MiB | next multiple of 1 MiB ≥ `L` |

- `plain_len` comes from the size block (decrypt with `K_size`). A file whose length is not `stage(L)` → `InvalidFormat`.
- Bytes between `L` and `stage(L)` are random and never read. Changing them has no effect and is not detected (it reveals nothing).
- **getattr** on a padded vault reads and decrypts the first 89 bytes of each file. On a vault without padding it stays pure arithmetic.
- **Writing:** every change of `plain_len` writes a new size block with a fresh nonce. A crash in the middle can make this one file unreadable (`EIO`, reported by `check`), the same risk class as a torn chunk (base spec §8). The flush order is:
  - **Grow past the current stage:** first extend the real file to the new stage length and fill `[old real length, new stage)` with random bytes; then write the chunks; then write the header and the size block.
  - **Shrink:** write the chunks, then the header and size block, then `set_len` to the new stage, then fill the bytes after the end of the last chunk with random bytes (so no old chunk bytes stay in the padding).
- **getattr on a file that cannot be opened** (for example permission denied): the size block is out of reach, so the reported size is an upper bound, `real length − 89 − 28`.

## 6. Key file `.cd-key` (replaces the password payload of base spec §4.3)

The file header and slot frame stay as in base spec §4.3. Payload `password` (type 1) is now variable length:

```
0       4       argon2_m_kib
4       4       argon2_t
8       4       argon2_p
12      16      salt
28      12      nonce
40      …       wrapped = AES-256-GCM(KEK, nonce, key_set, AD)
key_set = count (u8, 1 or 2) ‖ count × ( epoch (u32) ‖ MK (32 B) )
```

- `payload_len` = 40 + 1 + 36·count + 16, so 93 or 129 bytes.
- `AD` is unchanged: file bytes 0–9 ‖ `slot_type` ‖ `payload_len` ‖ payload bytes 0–39.
- After decryption: `count` must be 1 or 2, epochs must be > 0 and in strictly ascending order (so they are also different; the decoder rejects any other order). Otherwise → `WrongPassword` (cannot be told apart from a damaged file).
- Argon2 limits (MIN/MAX) and all other rules of base spec §4.3 stay.

## 7. Recovery key (base spec §4.8)

- The encoding is unchanged and holds **one** MK, the one of the vault's current epoch (`recovery-key` prints it).
- `recover` uses the vault's current epoch (the epoch in the marker) for the key set it writes.
- `recover` builds the key set `{ (marker.epoch, MK) }` and verifies the marker tag. If the tag does not match, the message is: "the recovery key does not belong to this vault, or it is from before the last key rotation". Nothing is written.
- While a rotation is running (section 9), the marker still holds the old epoch, so the **old** recovery key is the one that `recover` checks against the marker. `rotate-key` says this when it prints the new key.
- **Unfinished rotation.** A key set `{e}` alone would make every entry already written with `e+1` unreadable, and a later `rotate-key` would start a fresh `e+1` (permanent loss). So after the given key is verified against the marker tag (marker epoch `e`), `recover` walks the real tree with `K_names[e]`. The rotation is **unfinished** if:
  - (i) a real name that should be an encrypted name (a short entry name not starting with `.`, with the prefix candidates of conflict copies, or the full name in the `.cd-name` of a `.cd-cdl` entry that holds data, that is `.cd-content` or `.cd-dir`) does not decrypt with `K_names[e]` under its parent's directory id; foreign and control entries are skipped as the listing skips them, and so are `.cd-cdl` entries without data (a leftover of an interrupted create; a rotation leaves them alone, and nothing can be lost there); or
  - (ii) a file header (a short content file or `.cd-content`) has an epoch other than `e`.
  - The walk enters every real directory, also one whose name did not decrypt (its `.cd-dir` gives the id of its children), so a rotation that renamed only directories so far is found too.
  - `recover` holds the vault lock from before the walk until the key file is written, so no mount or rotation changes the tree in between. A vault in use gives: "the vault is in use (mounted, or a key rotation runs); stop it first".
  - Known gap: a crash inside the rotation's move of a long directory, after the rename to the new hash name and before the new `.cd-name` is written, leaves a `.cd-cdl` entry whose real name is not the hash of its (old) `.cd-name`. If that was the only change so far, the walk finds nothing, and `recover` writes `{e}`. No data is lost, but that directory stays hidden and blocks every later rotation (HS 9.4). The same state can come from a crash in a normal mount rename, so it cannot count as a sign of a rotation. A repair tool is a follow-up.
- **Unfinished:** `recover` needs the **new recovery key** too: `--new-recovery-key-fd N`, or a second prompt on a terminal ("Recovery key of the unfinished rotation: "). Without it the message is: "a key rotation is unfinished: give both recovery keys (old and new), or finish the rotation first". The new key must be shown to be right: a name decrypts with its `K_names[e+1]`, or a file of epoch `e+1` authenticates with it (header and first chunk). Otherwise: "the new recovery key does not belong to the unfinished key rotation of this vault". Then `recover` writes the key set `{e, e+1}`, and `rotate-key` can finish the rotation. Nothing is written on any error.
- **Not unfinished:** the given key is enough and `recover` writes `{e}`, also when the old key file holds two keys. Examples: a crash right after the rotation wrote the key file (nothing uses `e+1` yet; the next `rotate-key` starts again), or a crash between the marker write and the final key file write (the marker is already at `e+1` and all data too; the new recovery key alone works). A given `--new-recovery-key-fd` is then not read.

## 8. Rollback (documentation only)

The threat model (base spec §2) says clearly: replacing a file with an **older valid version of itself** (for example from a cloud version history) is **not detected**, also not after this spec. There is no write counter and no local state. A rotation (section 9) makes old versions unreadable only if they were encrypted with a removed epoch.

## 9. Key rotation: `crypto-drive rotate-key`

### 9.1 Command

```
crypto-drive rotate-key <vault-dir> [--key-file PATH] [--password-fd N] [--argon2-memory …] [--argon2-iterations …] [--argon2-parallelism …] [--yes]
```

- A run on a vault whose key set has one key always **starts a new rotation**; a run on a key set with two keys continues the unfinished one. Because starting one is expensive, the command asks `Continue? [y/N]` on a TTY; without a TTY it needs `--yes`.

- Runs **offline**: it takes the vault lock (base spec, mount lock). A mounted vault → "vault is already mounted".
- The password stays the same. Argon2 parameters may be set again (same rules as `passwd`).
- Progress (number of entries done) goes to stderr. The new recovery key goes to stdout as `RECOVERY KEY: <key>` with the note: "Keep the old recovery key until the rotation has finished."
- Exit 0 when finished, 2 on any error. Running it again continues an unfinished rotation.
- At start it prints a warning: "Do not use this vault on any other device until the rotation has finished. Afterwards every device needs the new key file. Your sync client will upload the whole vault again."

### 9.2 Steps

Let `e` be the current epoch (from the marker).

1. **Begin** (only if the key set has one key): make `MK_{e+1}`, write the key file atomically with the key set `{e, e+1}` (every password slot, same password, possibly new Argon2 parameters). Print the new recovery key.
   - If the key set already has two keys `{e, e+1}`, this is a resumed run: skip to step 2. (The recovery key of `e+1` was printed in the first run; `recovery-key` can show the **old** one only, since the marker still says `e`; after the rotation it shows the new one.)
2. **Re-encrypt**, depth first from the root, one entry at a time:
   - Leftover `.cd-rot.tmp` files (from a crash) are removed first.
   - **Directory:** encrypt its name again with `K_names[e+1]` and the same `dir_id`, then rename the real entry (switch between short and long layout as base spec §5.5 rename does). `.cd-dir` is not touched.
   - **File:** write the content again into `.cd-rot.tmp` in the same real directory: new header (epoch `e+1`, new `file_nonce`, **same `file_id`**), all chunks, padding if the vault is padded. `fsync`. Then make the new entry with the name encrypted under `K_names[e+1]` (short: `renameat` the tmp file to the new real name; long: create the overflow entry, write `.cd-name`, `renameat` the tmp file to `.cd-content`), then remove the old entry.
   - An entry whose name already decrypts with `K_names[e+1]` (and, for files, whose header says epoch `e+1`) is already done and is skipped.
   - **Duplicate after a crash:** two entries in the same directory that decrypt to the same clear name and the same entry id, one at epoch `e` and one at `e+1`. Both copies are fully authenticated (every chunk) and their plaintext is compared:
     - equal: the old-epoch copy is removed;
     - different (the file was edited during a mount between two runs): both are kept. The old copy is encrypted again under a new entry id with the name `<stem> (rotation conflict N)<.ext>`, so no change is lost;
     - the `e+1` copy fails authentication: it is removed and the file is done again; the `e` copy fails: it is removed.
3. **Finish:**
   - Walk the whole tree again. If any name, file or overflow entry still uses epoch `e` → stop with an error ("N entries still use the old key; run rotate-key again"); nothing else changes.
   - Write `.cd-vault` with epoch `e+1` and a new tag (atomic).
   - Write the key file with the key set `{e+1}` only (atomic).
   - A crash between these two writes is fine: the key set still has both epochs, and the next run sees the marker at `e+1` and only writes the key file.

### 9.3 Mounting during an unfinished rotation

If the key set has two epochs (a rotation did not finish), `mount`, `check` and the core work normally:

- names and files of both epochs are read;
- new names, renames and new files use the write epoch `e+1`;
- an existing file of epoch `e` that is changed keeps epoch `e` (its own `K_file`); the next `rotate-key` run converts it;
- `check` reports `rotation-in-progress` (warning).

### 9.4 Errors and limits

- **Entries that stop or block the rotation:**
  - An old-epoch file whose content does not authenticate **stops the run** at that file with an error ("authentication failed for <real name>"). Nothing after it is converted in that run. The user must remove or restore the file (`check` lists it) and run `rotate-key` again.
  - An old-epoch long entry with a wrong hash blocks the finish step (it is counted in "N entries still use the old key").
  - A long entry without a valid `.cd-name` (missing, not readable, or it does not decrypt) that still holds `.cd-dir` or `.cd-content` also blocks the finish step, because its data would be lost with the old key. The error names its real path. The user must repair or remove it.
  - Foreign entries, and incomplete entries that hold no data, are left untouched and do not block.
- **Rename order of a mount:** a short directory that gets a long name first gets its `.cd-name` (atomic write into the short directory) and is then renamed to the long entry name. A crash leaves at most a short directory with a stray `.cd-name`, which is ignored; it never leaves a long entry without a name that hides the directory and its children.
- **Read-only directories:** a real directory that cannot be written (for example mode `0555`) stops the rotation with "permission denied" when an entry in it must be renamed or written again. Make it writable and run `rotate-key` again.
- **What changes:** directory mtimes change during a rotation (entries are renamed or replaced). File mode and times are kept.
- The new recovery key is printed right at the start of the run, even if the run fails later.
- The vault lock is local. Another device that writes to the vault during a rotation can leave epoch-`e` entries behind. If that happens after the finish step, those entries cannot be read any more; `check` reports them as `unknown-key-epoch`. This is documented, together with the rule "stop all other devices first".
- A device that uses `--key-file` with a copy outside the vault needs the new key file after the rotation; the old one gives `WrongKey`.
- Rotation does not undo past leaks: whoever copied old ciphertext together with an old key can still read that old copy.

## 10. Check (base spec §7 `check`), new findings

| Kind (CLI text) | Severity | Meaning |
|---|---|---|
| `entry-id-mismatch` | error | name and file header (or `.cd-dir`) carry different entry ids |
| `unknown-key-epoch` | error | a name or file uses an epoch that is not in the key set |
| `rotation-in-progress` | warning | the key set has two epochs |
| `invalid-padding` | error | a padded file's length is not `stage(L)`, or its size block does not decrypt |

The existing findings stay. `check` never writes.

## 11. CLI changes (base spec §7)

- `init` gets `--pad-sizes`.
- `rotate-key` as in section 9.1.
- `passwd` keeps the key set it unlocked (one or two epochs) and wraps it with the new password.
- `recovery-key` prints the MK of the marker's epoch.
- `recover` as in section 7.

## 12. Documentation

- Base spec: §1.2 decisions, §2 threat model (file and directory swaps are now detected; rollback is not; what `--pad-sizes` hides and does not hide; rotation does not undo past leaks), §4 format (replaced by sections 2–7 of this spec), §7 CLI.
- `docs/format.md`: the new format, normative.
- `README.md`: `--pad-sizes`, `rotate-key` with the multi-device rules, the rollback limit.

## 13. Tests

- **Known-answer tests:** `scripts/kat/gen_vectors.py` implements sections 2–7 again in Python (entry id in the name, `K_file`/`K_size` with `file_id`, epoch in the HKDF salt, size block, key set in the slot, marker with flags and epoch). `crates/crypto-drive-core/tests/kat.rs` checks Rust against these values.
- **Golden vaults:** two, made with `CRYPTO_DRIVE_WRITE_GOLDEN=1`: `tests/golden/v1/plain/` and `tests/golden/v1/padded/` (each with `vault/` and `key`). The old golden files are removed.
- **Tamper tests**, each must fail and never return other bytes:
  - file content swapped under another file's name (same directory and across directories);
  - directory swapped with another directory (both `.cd-dir` and children moved);
  - header `file_id`, header `epoch`, size block changed;
  - padded file cut or grown;
  - key set with count 0 or 3, or two equal epochs (re-encrypted with the right KEK in the test).
- **Rotation tests:**
  - full rotation, then: old key file → `WrongKey`, old recovery key → refused, new one works, all data the same, `check` clean;
  - a crash after every step: a test-only failure hook (compiled only with `cfg(test)` or the `test-util` feature) stops the run at step N; then `rotate-key` runs again and the result is compared with the model;
  - mount-free reads and writes through `CryptoFs` while two epochs are present;
  - rotation of a padded vault keeps padding.
- **Model test** (`tests/model.rs`) also runs on a padded vault.
- **CLI tests:** `init --pad-sizes`, `rotate-key` (password from fd, needs `--yes` without a TTY, prints a recovery key), the new `recover` message.
- All existing tests are updated to the new format and must pass; `scripts/smoke-test.sh` gets one `rotate-key` step and one padded vault run.

## 14. Fuzzing

### 14.1 Why

Every byte of a vault comes from an untrusted place (a cloud, a USB stick). Rust prevents memory corruption, but not panics (a panic in a FUSE thread breaks the drive), endless loops, huge memory requests (the review found one: Argon2 parameters in a hostile key file) or wrong acceptance of damaged data. Fuzzing feeds millions of generated inputs to the parsers and looks for exactly these failures.

### 14.2 Tools and layout

- `cargo-fuzz` 0.13.2 (libFuzzer) with `libfuzzer-sys = "0.4.13"` and `arbitrary = "1.5.0"` (feature `derive`) for structured inputs.
- libFuzzer needs **Rust nightly**. Only the fuzz crate uses it: `fuzz/rust-toolchain.toml` pins `nightly-2026-10-15`. The main workspace stays on stable 1.99.1.
- `fuzz/` is its own Cargo workspace (`[workspace]` in `fuzz/Cargo.toml`, own `Cargo.lock`), excluded from the main workspace, with `crypto-drive-core = { path = "../crates/crypto-drive-core", features = ["test-util"] }`.
- Every file in `fuzz/` gets the license header.
- `scripts/fuzz.sh <target> [seconds]` runs one target (default 60 s); `scripts/fuzz.sh all [seconds]` runs every target one after another. It passes `-rss_limit_mb=2048 -timeout=10` and uses `fuzz/corpus/<target>/` as the corpus.
- Seed corpora come from the golden vaults and the known-answer vectors (section 13); `fuzz/seeds.sh` (or a small Rust helper) copies them into `fuzz/corpus/`. Generated corpora and `fuzz/artifacts/` are git-ignored; only the seed copies are committed.

### 14.3 Targets

| Target | Input | Must hold |
|---|---|---|
| `key_file` | raw bytes | `KeyFile::from_bytes` never panics; if it parses, `from_bytes(to_bytes(k)) == k` byte for byte. No Argon2 run (too slow). |
| `key_set` | raw bytes | the decoder of a decrypted key set (section 6) never panics and accepts only count 1 or 2 with strictly ascending epochs > 0. |
| `vault_marker` | raw bytes | `parse_unverified` and `verify` (fixed test keys) never panic; a parsed marker serializes back to the same bytes. |
| `recovery_key` | UTF-8 text | `decode_recovery_key` never panics; a decoded key encodes back to a string that decodes to the same key. |
| `names` | arbitrary `(dir_id, text)` | `NameCipher::decrypt` (fixed key) never panics on any text; for a valid clear name, `decrypt(encrypt(x)) == (entry_id, NFC(x))`. |
| `conflict_names` | text | `short_candidates`, `long_candidate`, `conflict_display_name` never panic; every candidate prefix is B64 only and at least `MIN_ENCODED_LEN` long. |
| `content` | raw bytes + `u64` | `plaintext_size`, `stage()`, `FileHeader::parse`, size block decrypt and `ChunkCipher::open` (fixed keys) never panic; `stage(L) >= L`, `stage` grows with `L`; an opened chunk round-trips. |
| `hostile_tree` | arbitrary tree: entries with arbitrary real names (incl. `.cd-*`), kinds and byte contents | written into a fresh test vault directory; then `check_vault`, `CryptoFs::readdir` of every directory, `getattr` and a full `read` of every listed file never panic and finish within the timeout. |
| `fs_ops` | arbitrary list of operations (like `tests/model.rs`) | run against `CryptoFs` and an in-memory model, also on a padded vault; results must match; no panic. |

### 14.4 What counts as done

- Every target builds and runs. In this environment each target runs at least 5 minutes without a finding (`scripts/fuzz.sh all 300`); the result is written into the plan's final report.
- Every finding is fixed in the core, and the input that found it becomes a normal regression test (a `#[test]` with the bytes) in the main workspace, so it is checked without nightly.
- `README.md` gets a short "Fuzzing" section (install nightly and cargo-fuzz, run the script).
