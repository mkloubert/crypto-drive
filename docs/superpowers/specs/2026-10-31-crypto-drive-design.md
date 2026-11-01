# crypto-drive – Design Specification (MVP)

- **Date:** 2026-10-31
- **Status:** Approved
- **Project license:** AGPL-3.0-or-later
- **Author:** Marcel Joachim Kloubert

## 1. Goal and context

`crypto-drive` is a Rust program that provides a **readable and writable virtual drive**. Every file operation in the drive is mapped in real time to a real directory (the *vault*). In the vault, **file contents and file and directory names are encrypted**.

### 1.1 Requirements (from the owner)

- MVP for **macOS**. Later Linux (priority) and Windows 11+.
- Full CRUD inside the virtual drive, like in a normal directory.
- Encrypt contents **and** names. From the outside, everything is encrypted.
- As few separate metadata files as possible. Metadata in the file header is allowed.
- Usage: a local directory plus a strong key that is protected by a password.
- Fast, lightweight, secure, post-quantum safe where possible.
- Project name `crypto-drive`, license AGPL-3.0. Every own source file has the license header.
- All documentation and code are in simple English.

### 1.2 Decisions

| Topic | Decision |
|---|---|
| Use case | Cloud sync **and** local protection, both equally important → encrypt per file, control files never change after creation (sync safe), tolerate sync conflict copies |
| Mount backend for the MVP | **macFUSE + `fuser`** (same code on Linux with native FUSE). On macOS 26, optional use without a kernel extension via `-o backend=fskit` |
| Key file | Default (CLI, 2026-11-01): `~/.crypto-drive/keys/<YYYYMMDDhhmmsszzz>_<VAULT_NAME>.cd-key` (UTC, ms), outside the vault so it is not synced; all other commands need `--key-file`, except an old vault with `.cd-key` in its root. Any other place with `--key-file` |
| Entry binding | A random entry id is encrypted with each name and bound into the content (section 4.6). Format v1 has no old versions to migrate. |
| Size padding | Optional per vault, chosen at `init` with `--pad-sizes`, cannot be changed later |
| Master key rotation | Offline command `rotate-key`, resumable after a crash |
| Rollback | Only documented, not detected. No write counter |
| Asymmetric crypto | **Not in the MVP.** The format has key slots and version fields, so it can grow later (for example X-Wing for "write without read") |
| Binding names to their directory | **Directory ID file** `.cd-dir` in each directory (never changes) |
| Long names | **Overflow directory** `.cd-cdl<hash>` |
| Control files | All start with `.cd-` |
| Max length of encrypted names | Default 220, can be set with `--max-name-length` at `init` |
| MVP scope | CLI: `init`, `mount` (also `--daemon`), `unmount`, `passwd`, `rotate-key`, `recovery-key`, `recover`, `check`. Password from TTY, `--password-fd`, or an environment variable |

### 1.3 Not in the MVP

- No GUI, no tray icon, no macOS keychain.
- No asymmetric keys, no sharing with more users.
- **xattrs are kept in memory only** while mounted (never on disk, gone at unmount). Copy tools abort on any xattr error and Finder reads its own copy markers back, so set values must be readable again. Limits: 1 MiB per entry, 64 MiB in total; a value over a limit is accepted and not kept. Linux keeps only `user.*`. No **symlinks**, **hard links** or special files (returns `EPERM`). No `chown` (returns `EPERM`).
- No Windows backend (WinFsp comes later as its own crate).
- `check` only reports. It does not repair (`--repair` comes later).
- Number of files, tree structure and timestamps are not hidden. File sizes are hidden only in a vault made with `--pad-sizes`, and then only roughly (section 2).

## 2. Threat model

**Protected** against an attacker who can read and change the vault (cloud provider, stolen disk, backup):

- Confidentiality of file contents and of file and directory names.
- Integrity: every change is detected on read and gives an error, never wrong plaintext. This covers bit flips, swapped or cut chunks, chunks mixed between files, and files moved between directories.
- **File and directory swaps are detected.** Content is bound to its name through the entry id (section 4.6). Replacing the encrypted file `B` with a copy of another file `A` gives an error, not A's content under B's name. The same holds for a directory and its subtree.
- The key file is stored **outside** the vault by default (`~/.crypto-drive/keys`, or `--key-file`), so an attacker with only the vault cannot run an offline attack on the password.

**Visible** from the outside: rough file sizes (±28 bytes per 64 KiB), number of files and directories, nesting depth, timestamps, times of changes.

**`--pad-sizes`** (optional, set at `init`) rounds every file up to a stage: 4 KiB, then powers of two up to 1 MiB, then multiples of 1 MiB. It hides the exact size inside a stage. It does **not** hide the number of files, the tree shape, timestamps, times of changes, or the stage itself (so a size is known up to a factor of 2 below 1 MiB, and up to 1 MiB above). It costs disk space (every file takes at least 4 KiB, up to about 2x its size below 1 MiB, up to 1 MiB more above) and `getattr` has to read the first 89 bytes of every file.

**Not protected** against:
- An attacker with access to the running, unlocked system (malware, root, the same user while the drive is mounted).
- **Rollback** of a single file to an older, valid version (for example from the version history of a cloud). This is a known limit of per-file encryption. There is no write counter and no local state.
- **Old key files after a password change:** `passwd` does not change the master key. Someone with an old copy of `.cd-key` (for example from cloud version history) and the old password can still open the vault. `rotate-key` fixes this for the future.
- **Past leaks, even after rotation:** `rotate-key` makes old key files, old passwords and old recovery keys useless for the vault as it is after the rotation. Whoever already copied old ciphertext together with an old key can still read that old copy.
- **Outside changes the running drive does not see at once:** the drive notices outside changes through the mtime of the real directory (section 5.2). A change in the same mtime tick as an own change (coarse on FAT: 2 s), or a change that does not touch the parent directory's mtime (inside an overflow entry, a `chmod` of an entry), can stay unseen until the parent directory changes. This is a freshness limit, not a break of integrity: what is read is always authenticated.

**Post-quantum:** The MVP uses only symmetric primitives with 256-bit keys (AES-256, HMAC-SHA-256, HKDF-SHA-512, Argon2id). Grover's algorithm reduces the security to about 128 bits at most. So the design is quantum safe. There are no asymmetric algorithms that a quantum computer could attack.

## 3. Architecture

Cargo workspace:

```
crypto-drive/
├── Cargo.toml                  # workspace, dependency versions
├── Cargo.lock                  # committed, pins exact versions
├── rust-toolchain.toml         # pinned stable Rust version
├── deny.toml                   # license and advisory checks
├── crates/
│   ├── crypto-drive-core/      # library, platform independent, no FUSE
│   ├── crypto-drive-fuse/      # adapter fuser → core (macOS + Linux)
│   └── crypto-drive/           # binary: CLI, password input, daemon
├── docs/format.md              # normative format specification (from section 4)
└── scripts/                    # smoke test, license header check
```

**Crate dependencies:** `crypto-drive` → `crypto-drive-fuse` → `crypto-drive-core`. The core does not depend on FUSE and can be fully tested without a mount.

**Platform layer:** All access to the real directory goes through one module in the core (`backing`). It uses directory handles (`openat` and friends). It is the only part that must be ported for Windows.

**External crates:** stable versions only, AGPL compatible licenses, checked by `cargo deny`. Exact versions are pinned in `Cargo.lock`.

## 4. On-disk format (version 1)

All integers are **little endian** unless noted. "B64" means Base64url **without** padding (alphabet `A–Z a–z 0–9 - _`).

### 4.1 Vault layout

```
<vault>/
├── .cd-vault                    # marker, changes only on key rotation
├── .cd-key                      # key file (not present when --key-file points elsewhere)
├── <B64 name>                   # encrypted file
├── <B64 name>/                  # encrypted directory
│   ├── .cd-dir                  # directory ID, never changes
│   └── …
└── .cd-cdl<B64 hash>/           # overflow entry (file or directory)
    ├── .cd-name                 # full B64 name (ASCII)
    ├── .cd-content              # only for a file: encrypted content
    └── .cd-dir                  # only for a directory: directory ID; children are next to it
```

**Name rule:** Encrypted names never contain a dot. Entries that start with `.cd-` are control files. All other entries that start with a dot (for example `.DS_Store`) are foreign and hidden in the drive.

### 4.2 Key epochs and key hierarchy

Every master key belongs to a **key epoch**, a `u32` that starts at 1 at `init` and grows by 1 with each rotation (section 7, `rotate-key`).

```
password ──Argon2id(salt, m, t, p)──► KEK (32 B)
KEK ──AES-256-GCM unwrap──► key set = { (epoch, MK_epoch), … }   (1 or 2 entries)

For each epoch e in the key set:
PRK_e        = HKDF-SHA-512-Extract(salt = vault_id ‖ e (u32), ikm = MK_e)
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
- All random numbers come from the operating system (`getrandom`).

### 4.3 Key file `.cd-key`

```
offset  length  field
0       8       magic = "CD-KEY\0\0"
8       2       version = 1
10      2       slot_count (≥ 1)
12      …       slots
```

Slot:
```
0       1       slot_type (1 = password)
1       2       payload_len
3       …       payload
```

Payload `password` (type 1), 93 bytes (one key) or 129 bytes (two keys):
```
0       4       argon2_m_kib
4       4       argon2_t
8       4       argon2_p
12      16      salt
28      12      nonce
40      …       wrapped = AES-256-GCM(KEK, nonce, key_set, AD)   # key_set + 16 B tag
key_set = count (u8, 1 or 2) ‖ count × ( epoch (u32) ‖ MK (32 B) )
```

- `payload_len` = 40 + 1 + 36·count + 16.
- After decryption `count` must be 1 or 2, and the epochs must be > 0 and in strictly ascending order. Otherwise the unlock fails like a wrong password.
- `AD` = file bytes 0–9 (magic and version) ‖ `slot_type` ‖ `payload_len` ‖ payload bytes 0–39. This protects the version and the Argon2 parameters against changes. `slot_count` is not part of the AD, so slots can be added later without breaking others.
- **Default parameters:** m = 262144 KiB (256 MiB), t = 3, p = 4. They can be set at `init`, `passwd`, `recover` and `rotate-key` (`--argon2-memory`, `--argon2-iterations`, `--argon2-parallelism`). Limits: m 19456 … 1048576 KiB, t 2 … 64, p 1 … 64. Values below the default print a warning. A slot above the maximum is skipped without running Argon2.
- **Unlock:** try all `password` slots. Skip unknown slot types (forward compatibility). Keep them unchanged when the file is written again.
- The key file is not bound to one vault. `.cd-vault` checks that key and vault belong together.
- Always written atomically: temporary file in the target directory, `fsync`, `rename`, `fsync` of the directory. File mode `0600`.

### 4.4 Vault marker `.cd-vault` (66 B)

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

- Mount is refused if the tag is wrong ("key does not belong to this vault"), the key set has no key for `epoch`, a flag bit is unknown, or the `format_version` is unknown.
- The file is written by `init` and by the last step of `rotate-key` only (atomic). It changes only on rotation. `pad_sizes` is chosen at `init` and cannot be changed later.

### 4.5 Directory ID `.cd-dir` (16 B)

- 16 random bytes `dir_id`. The root has no `.cd-dir`. Its `dir_id` is the `vault_id`.
- Written atomically by `mkdir` and never changed afterwards.

### 4.6 Names and entry binding

Every entry has a 16-byte **entry id**: for a file the random `file_id` stored in its header (section 4.7), for a directory its `dir_id`.

```
enc   = AES-256-SIV(K_names[e], AD = [parent_dir_id], entry_id ‖ NFC(clear_name))   # 16 B tag + ciphertext
name  = B64(enc)
```

- The children of the root use `parent_dir_id = vault_id`.
- Decrypting gives the entry id (first 16 bytes) and the clear name. Fewer than 17 plaintext bytes → `AuthFailed`.
- **Which epoch:** a real name carries no epoch. The reader tries `K_names[e]` for every epoch in the key set, highest first.
- If `len(name) ≤ max_name_length` (default 220, reached from about 135 clear bytes), the entry is `name`.
- Otherwise the entry is `".cd-cdl" + B64(SHA-256(name))` (50 characters) and `.cd-name` holds `name`.
- Clear names are normalized to **Unicode NFC** before encryption. Invalid names: empty, `.`, `..`, names with `/` or NUL, names longer than 1024 bytes.
- **Case:** The virtual drive is **case sensitive**. On a case-insensitive real file system (APFS default, NTFS), two B64 names that differ only in case are practically impossible because of the 128-bit SIV tag.
- A clear name that starts with `.cd-` is allowed inside the drive. After encryption it has no dot.

**Binding checks:**

- **File:** the `file_id` in the file header must equal the entry id in the name. Otherwise → `AuthFailed`. The `file_id` is part of `K_file`, so it cannot be changed unnoticed.
- **Directory:** the canonical `.cd-dir` must hold the entry id of the name. Otherwise → `AuthFailed`.
- **Rename and move** encrypt the name again with the same entry id. Content and `.cd-dir` are not touched, so the cost stays O(1).
- **Copy inside the drive** creates a new file and so a new `file_id`.
- **Conflict copies** from sync clients keep working: name and content come from the same real entry.

This detects one file's content under another file's name (in any directory) and one directory's subtree under another directory's name. It does not detect rollback (section 2).

### 4.7 File content

File (or `.cd-content` inside an overflow directory):
```
header, not padded (53 B):  version (1 B) = 1 ‖ epoch (u32) ‖ file_nonce (32 B, random) ‖ file_id (16 B, random)
header, padded (89 B):      the 53 bytes ‖ size block (36 B)
size block:                 nonce (12 B, random) ‖ AES-256-GCM(K_size, nonce, plain_len (u64), AD = header bytes 0–52) ‖ tag (16 B)
chunks:                     chunk_0 ‖ chunk_1 ‖ … ‖ chunk_{n-1}
chunk_i:                    nonce (12 B, random) ‖ AES-256-GCM(K_file, nonce, P_i, AD_i) ‖ tag (16 B)
AD_i:                       chunk_index (u64, big endian) ‖ is_last (u8: 1 for i = n-1, else 0)
padding:                    random bytes (padded vault only)
```

- Clear chunk size `S = 65536`. All chunks except the last are full. The last holds 1…S bytes. It is empty only for an empty file (n = 1, `P_0` empty).
- Every write of a chunk uses a **new random nonce**. Because each file has its own key, this is safe for about 2³² chunk writes per file.
- Content and name are independent. A file can be renamed or moved without touching its content.
- The `epoch` in the header selects `K_content[epoch]`. It is also part of the size block AD.

**Not padded:** an empty file has 53 + 28 = 81 bytes. With `C` = ciphertext size, `n = ceil((C − 53) / (S + 28))` and clear size `= C − 53 − 28·n`. Invalid: `C < 81`, a last chunk with fewer than 29 bytes when n > 1, an unknown `version`.

**Padded (`pad_sizes` flag):** `L = 89 + size of the chunks` is the unpadded length. The real file length MUST be `stage(L)`:

| `L` | `stage(L)` |
|---|---|
| ≤ 4096 | 4096 |
| ≤ 1 MiB (1048576) | next power of two ≥ `L` |
| > 1 MiB | next multiple of 1 MiB ≥ `L` |

- The clear size comes from the size block. A file whose length is not `stage(L)` → `InvalidFormat`.
- The bytes between `L` and `stage(L)` are random and never read.
- `getattr` reads and decrypts the first 89 bytes of each file. On a vault without padding it stays pure arithmetic. If a padded file cannot be opened (permission denied), `getattr` reports the upper bound `real length − 89 − 28`.
- Every change of the clear size writes a new size block with a fresh nonce. Flush order when the file grows past its stage: extend the real file and fill the new range with random bytes, write the chunks, then write the header and size block. Shrink: chunks, header, `set_len`, then random bytes from the end of the last chunk. A crash in the middle can make this one file unreadable (`EIO`, reported by `check`).

### 4.8 Recovery key

- Encoding: `MK (32 B) ‖ SHA-256(MK ‖ "crypto-drive v1 recovery")[0..2]` → 34 B → Base32 (Crockford alphabet, upper case, no padding) → 55 characters in groups of 5, joined with `-`.
- On input, case, spaces and dashes are ignored. `I` and `L` are read as `1`, and `O` as `0`. The checksum is verified.
- It holds **one** MK, the one of the vault's current epoch. It is **as powerful as the master key** and must be stored offline.
- `recover` builds the key set `{ (marker.epoch, MK) }` and verifies the marker tag. If the tag does not match, it says: "the recovery key does not belong to this vault, or it is from before the last key rotation". Nothing is written.
- While a rotation is running, the marker still holds the old epoch, so the **old** recovery key is the one checked against the marker. If the rotation is unfinished, `recover` also needs the **new** recovery key and writes the key set `{e, e+1}` (hardening spec §7).

### 4.9 Key rotation

`crypto-drive rotate-key` replaces the master key and re-encrypts the whole vault, **offline** (it takes the vault lock). It is resumable after a crash.

1. **Begin** (key set has one key): make `MK_{e+1}`, write the key file atomically with the key set `{e, e+1}`, print the new recovery key at once (even if the run fails later).
2. **Re-encrypt**, depth first: a directory gets its name encrypted again under `K_names[e+1]` with the same `dir_id`. A file is written again to `.cd-rot.tmp` (new header with epoch `e+1`, new `file_nonce`, same `file_id`, all chunks, padding if padded), `fsync`, then the new entry is made and the old one removed. Entries that are already done are skipped.
3. **Finish:** walk the tree again; if anything still uses epoch `e`, stop with an error. Otherwise write `.cd-vault` with epoch `e+1`, then the key file with `{e+1}` only.

- **Duplicates after a crash:** both copies are fully authenticated and their plaintext is compared. Equal: the old copy is removed. Different (edited during a mount between two runs): both are kept, the old one as a new file `<stem> (rotation conflict N)<.ext>`. A copy that fails authentication is dropped.
- **Unfinished rotation:** `mount`, `check` and the core work with both epochs. New names and new files use epoch `e+1`; a changed file of epoch `e` keeps its epoch until the next `rotate-key` run. `check` reports `rotation-in-progress`.
- Old-epoch entries that cannot be decrypted (or long entries with a wrong hash) block the finish step; the user must remove them (`check` lists them). Foreign and incomplete entries are left alone and do not block.
- Directory mtimes change during a rotation. File mode and times are kept.
- Another device that writes during a rotation can leave epoch-`e` entries behind; after the finish step they cannot be read (`check`: `unknown-key-epoch`). Stop all other devices first.
- Rotation makes old key files, old passwords and old recovery keys useless. It does not undo past leaks: whoever copied old ciphertext together with an old key can still read that old copy.

## 5. File system logic (core)

### 5.1 API

Path based, with clear paths relative to the drive root:

`getattr`, `readdir`, `create`, `open`, `read`, `write`, `flush`, `fsync`, `release`, `truncate`, `set_times`, `set_mode`, `mkdir`, `rmdir`, `unlink`, `rename`, `statfs`.

### 5.2 Path resolution

- Walk component by component from the root. Read the `dir_id` (`.cd-dir`) of each directory. A real name contains the random entry id, so it cannot be computed from the clear name. Every lookup uses the **name index** of the directory instead (below).
- All access to the real file system is **relative to directory handles** (`openat`, `renameat`, `unlinkat`, `mkdirat`). So `PATH_MAX` does not apply.
- **Caches:**
  - LRU cache: clear directory path → directory state (`dir_id`s, directory handle, listing).
  - The directory state is dropped when the mtime of the real directory changed (for example when a sync client wrote from outside).
- **Name index:** every cached directory state holds a map: clear display name → (real name, layout, entry id, epoch). It is the listing of section 5.3 (conflict copies included, foreign entries skipped). It is built the first time the directory is needed: list the real directory and decrypt every name, O(n) once. There is no probing by encrypting a name.
  - Own changes update the index in place (create and mkdir insert, unlink and rmdir remove, rename removes from the source and inserts into the target). Then the mtime of the real directory is read again, so the own change does not count as an outside change. Creating N files in one directory builds the index once.
  - Limits: see the threat model (section 2), "Outside changes the running drive does not see at once".

### 5.3 readdir

1. List the real directory.
2. Skip `.cd-*` control files, but not `.cd-cdl*`.
3. Classify each entry:
   - **B64 name:** decrypt it.
   - **`.cd-cdl<hash>`:** read and decrypt its `.cd-name`.
   - **Conflict copy:** the name is valid B64 (or `.cd-cdl` + 43 characters) followed by a suffix. If the prefix decrypts, show the entry as `<stem> (conflict N)<.ext>`.
     - `N` starts at 1 and follows the sort order of the real names.
     - Suffixes of all sync clients are found the same way, with no special patterns per client.
     - Some suffixes contain only B64 characters (for example OneDrive `-DESKTOP1`). So prefixes are tried from longest to shortest until one authenticates. The AES-SIV check makes false matches practically impossible.
   - **Anything else** (foreign files, names that do not decrypt): hidden in the drive and reported by `check`.
4. **More than one `.cd-dir` (sync case):** If two devices create the same directory at the same time, the sync client can merge both directories. A conflict copy of `.cd-dir` (any control file whose name starts with `.cd-dir` and is 16 bytes long, except `.cd-dir.tmp`) appears next to it. readdir then tries all found `dir_id`s. New entries always use the canonical `.cd-dir`. `check` reports the case.

- **Plain name:** if two entries have the same clear name, which one gets the plain name is not defined. The other shows as `(conflict N)`.
- **Unreadable entries:** an unreadable long-name entry (for example mode 000) is hidden from listings and blocks creating other names that would also need a long entry in that directory. An unreadable short entry blocks only its own name.

Conflict copies can be read and written like normal files. Renaming one encrypts its name again with a clean name and so resolves the conflict.

### 5.4 Open files

- Each real file has **one** shared state (`Arc<Mutex<OpenFile>>`) for all handles. It holds `K_file`, a chunk cache and a dirty buffer.
- **read:** compute the chunk range from the offset. Read, authenticate and decrypt the chunks. Reads past the end return fewer bytes.
- **write:**
  - A partly written chunk is read, changed and encrypted again.
  - If the file grows, the old last chunk is written again with `is_last = 0`. Gaps are filled with encrypted zero chunks.
  - Changed chunks are kept in a dirty buffer (default at most 64 chunks = 4 MiB per file). They are written on `flush`, `fsync`, `release`, or when the buffer is full.
  - Until then, the size in memory is the reported size.
  - Files opened with `O_APPEND` always write at the current end.
- **truncate:**
  - Shrink: write the new last chunk again (`is_last = 1`) and cut the real file.
  - Grow: append zero chunks.
- **create:** write the header and an empty `is_last` chunk (81 B, or 4096 B in a padded vault).

### 5.5 Directory and name operations

- **mkdir:** create the real directory, then write `.cd-dir` atomically (temporary file `.cd-dir.tmp`, `fsync`, `rename`).
  - A directory without `.cd-dir` is incomplete. If it is empty and older than 60 seconds, it is removed on the next access. A younger one is not found and is kept (a sync client may not have written its `.cd-dir` yet). Otherwise `check` reports it, and access gives `EIO`.
- **rmdir:** A directory is empty when it holds only control files. Any other entry, also a foreign file, gives `ENOTEMPTY`. Remove `.cd-dir` first, then the directory.
- **unlink:** remove the file, or the overflow directory with its `.cd-content` and `.cd-name`.
- **rename:**
  - Same directory, both names short: one `renameat`.
  - Into another directory: encrypt the name again with the new `dir_id`, then `renameat`.
  - Directories move together with their `.cd-dir`. This is O(1).
  - Changing between a short and a long name needs more than one step. Replacing an existing target file is also not one atomic step: the replacing entry needs its own real name (the entry id is in the name), so the drive first moves, then removes the old target. The order is chosen so that a crash leaves at most a duplicate (shown as a conflict copy) or an orphan entry, never lost data: first build the target completely, then remove the source. A short directory that gets a long name first gets its `.cd-name`, then is renamed (hardening spec §9.4).
  - An existing target file is replaced (not atomic, see above). An existing empty target directory is replaced. A non-empty target directory gives `ENOTEMPTY`. Mixing a file and a directory gives `EISDIR` or `ENOTDIR`.
  - `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are not supported in the MVP (`EINVAL`).

### 5.6 Attributes

- `mode`, `uid`, `gid`, `atime`, `mtime` and `ctime` come from the real entry. `chmod` and `utimens` are passed through. `chown` gives `EPERM`.
- The size is computed as in section 4.7. While writes are pending, the size in memory is used.
- `statfs` is passed through from the real file system.

## 6. FUSE adapter (`crypto-drive-fuse`)

- Implements `fuser::Filesystem`.
- Keeps an inode table: inode ↔ clear path, with lookup counter and `forget`. On `rename`, the paths in the table are updated.
- Maps core errors to `errno` (see section 8).
- **Mount options:**
  - macOS: `volname=<vault directory name>`. Not `noappledouble`: it makes the kernel refuse `.DS_Store` and `._*` files, and Finder aborts a folder copy with -8062 when it cannot write the `.DS_Store` of the source. These files are stored encrypted like any other file.
  - always: `default_permissions`, `fsname=crypto-drive`
  - plus options passed with `-o` (for example `-o backend=fskit` on macOS 26)
- Attribute and entry TTL: 1 second.
- xattrs live in an in-memory table by clear path; rename moves them, unlink and rmdir drop them. `setxattr` honours `XATTR_CREATE` (`EEXIST`) and `XATTR_REPLACE` (`ENOATTR`, Linux `ENODATA`) and the macOS resource fork `position`; otherwise it succeeds, also when the value is not kept. `removexattr` of a missing name succeeds. `getxattr` and `listxattr` answer the size query (size 0) and return `ERANGE` for a too small buffer. `symlink`, `link` and `mknod` return `EPERM`.

## 7. CLI (`crypto-drive`)

```
crypto-drive init         <vault-dir> [--key-file PATH] [--max-name-length N] [--pad-sizes] [--argon2-* …]
crypto-drive mount        <vault-dir> <mountpoint> [--key-file PATH] [--daemon] [-o OPT …] [--debug]
crypto-drive unmount      <mountpoint> [--force]
crypto-drive passwd       <vault-dir> [--key-file PATH] [--argon2-* …]
crypto-drive rotate-key   <vault-dir> [--key-file PATH] [--password-fd N] [--argon2-* …] [--yes]
crypto-drive recovery-key <vault-dir> [--key-file PATH]
crypto-drive recover      <vault-dir> [--key-file PATH] [--overwrite] [--recovery-key-fd N] [--new-recovery-key-fd N] [--argon2-* …]
crypto-drive check        <vault-dir> [--key-file PATH]
```

**Password input**, for every command that needs a password:
1. `--password-fd N`
2. otherwise the environment variable `CRYPTO_DRIVE_PASSWORD` (prints a warning)
3. otherwise a TTY prompt

For the new password at `init`, `passwd` and `recover`, the same rules apply with `--new-password-fd N` and `CRYPTO_DRIVE_NEW_PASSWORD`. At the TTY, the new password is asked twice. Empty passwords are rejected. The recovery key at `recover` comes from `--recovery-key-fd N` or a TTY prompt.

- **init:**
  - The target directory must be empty or must not exist.
  - Creates the MK (epoch 1) and the `vault_id`, then `.cd-vault` and the key file. With `--pad-sizes` the marker gets the padding flag (cannot be changed later). With `--key-file` the key file is created at that path; without it the CLI creates `~/.crypto-drive/keys/<YYYYMMDDhhmmsszzz>_<VAULT_NAME>.cd-key` (folders 0700, file 0600, UTC time with milliseconds, `VAULT_NAME` = vault directory name with characters other than `[A-Za-z0-9_-]` as `_`) and prints its path. An existing key file is never overwritten. The core still uses `.cd-key` in the vault root when it gets no key file path; the other CLI commands take `--key-file`, or fall back to that old `.cd-key` if it exists.
  - Prints the recovery key **once** on stdout, with a note on stderr to write it down and keep it safe.
- **mount:**
  - With `--daemon`, the process forks **first, before any threads start**. The child asks for the password, unlocks and mounts. Then it tells the parent "mounted" through a pipe, calls `setsid` and redirects stdio to `/dev/null`. The parent exits with code 0 after "mounted", or with a code ≠ 0 and the error message.
  - Unlock: read the key file, unlock it, check `.cd-vault`.
  - `SIGINT` and `SIGTERM` lead to a clean unmount after all buffers are written. An unmount from outside (`umount`) ends the process too.
- **unmount:**
  - macOS: `umount <mountpoint>` (with `--force`: `umount -f`)
  - Linux: `fusermount3 -u <mountpoint>` (with `--force`: `fusermount3 -uz`)
  - A busy drive gives a clear message.
- **passwd:** unlock with the old password, then replace all password slots with one new slot. It keeps the key set it unlocked (one or two epochs). The master key stays the same (see the threat model); use `rotate-key` to replace it.
- **rotate-key:** see section 4.9.
  - Offline: it takes the vault lock; a mounted vault gives "vault is already mounted".
  - A key set with one key always starts a new rotation; a key set with two keys continues the unfinished one. Starting is expensive (the whole vault is written again and the sync client uploads it again), so the command asks `Continue? [y/N]` on a TTY. Without a TTY it needs `--yes`.
  - It prints a warning at start: no other device may use the vault until the rotation has finished, and afterwards every device needs the new key file.
  - The new recovery key goes to stdout as `RECOVERY KEY: <key>`, right at the start. Keep the old recovery key until the rotation has finished. Progress goes to stderr.
  - Exit 0 when finished, 2 on any error. Run it again to continue.
- **recovery-key:** unlock, then print the recovery key of the vault's current epoch on stdout.
- **recover:** read the recovery key, check its checksum and the `.cd-vault` tag (using the vault's current epoch), then write a new key file with a new password. An existing key file is only replaced with `--overwrite`. Without `--key-file` it targets the old `.cd-key` of the vault if there is one, else a new file in `~/.crypto-drive/keys`, and prints the path. During an unfinished key rotation it also needs the new recovery key (`--new-recovery-key-fd N` or a second TTY prompt; hardening spec §7).
- **check:**
  - Walks the whole tree and authenticates all names and all chunks.
  - Reports missing or multiple `.cd-dir`, orphan `.cd-cdl` entries, conflict copies, foreign entries, names that do not decrypt, files with an invalid size, and chunks that fail authentication.
  - New findings: `entry-id-mismatch` (error: name and file header or `.cd-dir` carry different entry ids), `unknown-key-epoch` (error: a name or file uses an epoch that is not in the key set), `rotation-in-progress` (warning: the key set has two epochs), `invalid-padding` (error: a padded file has a wrong length or a size block that does not decrypt).
  - It never writes.
  - Exit code 0 if nothing was found, 1 for warnings only, 2 for errors.

## 8. Error handling and hardening

| Core error | errno | Note |
|---|---|---|
| `NotFound` | `ENOENT` | |
| `AlreadyExists` | `EEXIST` | |
| `NotEmpty` | `ENOTEMPTY` | |
| `IsADirectory` | `EISDIR` | |
| `NotADirectory` | `ENOTDIR` | |
| `AuthFailed` | `EIO` | logged with the real (encrypted) path |
| `InvalidFormat` | `EIO` | |
| `NameTooLong` | `ENAMETOOLONG` | clear name > 1024 bytes |
| `InvalidName` | `EINVAL` | |
| `InvalidArgument` | `EINVAL` | |
| `Unsupported` | `ENOTSUP` | |
| `NotPermitted` | `EPERM` | |
| `Io(e)` | errno of `e` | |

- **Main rule:** plaintext that is not authenticated never leaves the core, not even in parts.
- **Messages at unlock:** "Wrong password or damaged key file", "The key does not belong to this vault", "Unknown format version". In all three cases nothing is written.
- **Crash consistency:** control files and key files are written atomically. Chunks are overwritten in place. A torn chunk gives `EIO` on read and is reported by `check`.
- **Secrets:**
  - Keys and passwords are kept in `Zeroizing` or `SecretBox` and are wiped when dropped.
  - Key memory is locked with `mlock` (best effort, with a warning on failure).
  - Comparisons run in constant time.
  - Core dumps are turned off (`RLIMIT_CORE = 0`).
- **Logging** contains no clear names by default. `--debug` turns on detailed logs with names and prints a warning at start.

## 9. Tests and quality

- **Toolchain:** `rustup`, current stable version, pinned in `rust-toolchain.toml`, with `rustfmt` and `clippy`. `cargo-deny` checks licenses and security advisories.
- **Unit tests per module:**
  - Key slots and Argon2 round trip (tests use the lowest allowed parameters).
  - Recovery key: encoding, checksum, tolerant input.
  - Names: round trip, NFC/NFD, emoji, the overflow limit (exactly `max_name_length`, ±1), detection of conflict suffixes (Syncthing, Nextcloud, Dropbox, OneDrive, iCloud, Google Drive).
  - Size formula.
- **Golden files:** two committed example vaults (`tests/golden/v1/plain` and `tests/golden/v1/padded` in the core crate) with key file, known password and fixed contents. All future versions must read it.
- **Tamper tests:** each of these changes must give an error (`AuthFailed`, `WrongKey` or `WrongPassword`), never wrong plaintext:
  - a bit flip in a header, chunk, name, `.cd-dir`, `.cd-vault` or `.cd-key`
  - swapped chunks
  - a file cut at a chunk boundary or down to the bare header
  - a file moved to another directory
  - chunk bytes swapped between two files (after their headers)
  - a wrong key
  - changed Argon2 parameters
- **Property tests (`proptest`):** random sequences of `write`, `read`, `truncate`, `rename`, `mkdir`, `unlink` and `rmdir` run against the core and against a simple in-memory model. The results must be the same, also after closing and opening the vault again.
- **CLI tests:** `init`, `passwd`, `recovery-key`, `recover` and `check` run in temporary directories, with the password from `--password-fd`.
- **Mount tests:** marked `#[ignore]`, they need FUSE (macOS host, or Linux with `/dev/fuse`). Also `scripts/smoke-test.sh`: mount, CRUD, rename, big files, `rsync` in and out, checksum compare, unmount.
- **Benchmarks (`criterion`):** throughput of chunk encryption and decryption, name operations, and sequential and random I/O through the core.
- **Static checks:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`, license header check.

**Development environment:**
- Work happens in Docker (Linux ARM64, no root, no `/dev/fuse`). Core, CLI and the build of the FUSE adapter are fully tested there.
- The macOS build and the mount tests run on the host with macFUSE (`brew install --cask macfuse`).

## 10. Repository rules

- Every own source file starts with the AGPL license header of the project. In Rust files, use `//` instead of `#` as the comment marker. In shell and TOML files, use `#`.
- `README.md` covers install, usage, threat model and what stays visible from the outside.
- `docs/format.md` holds the normative format specification (section 4).
- All docs, comments, messages and identifiers are in simple English.

## 11. Later features (not MVP)

- Windows backend (`crypto-drive-winfsp`)
- `check --repair`, for example to merge more than one `.cd-dir`
- encrypted xattrs (Finder tags) and encrypted symlinks
- asymmetric key slots (X-Wing) and "write without read"
- native FSKit backend
- keychain and Secret Service integration
- GUI
