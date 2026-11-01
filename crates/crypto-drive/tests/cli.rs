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

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const FAST: [&str; 6] = [
    "--argon2-memory",
    "19456",
    "--argon2-iterations",
    "2",
    "--argon2-parallelism",
    "1",
];

/// A HOME for the tests, so no test writes to the real
/// `~/.crypto-drive/keys`. Tests that look at HOME pass their own.
fn test_home() -> &'static Path {
    static HOME: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    HOME.get_or_init(|| tempfile::tempdir().unwrap()).path()
}

/// Runs the binary with `stdin` on fd 0 and without secrets from the parent.
fn run(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crypto-drive"));
    cmd.args(args)
        .env("HOME", test_home())
        .env_remove("CRYPTO_DRIVE_PASSWORD")
        .env_remove("CRYPTO_DRIVE_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    write_input(&mut child, stdin);
    child.wait_with_output().unwrap()
}

/// Writes `stdin` to the child and closes its input. A command that fails
/// early (for example "add --yes") exits without reading its input, so the
/// write can hit a closed pipe. That is fine: the tests check the exit code
/// and the output.
fn write_input(child: &mut std::process::Child, stdin: &str) {
    let mut input = child.stdin.take().unwrap();
    match input.write_all(stdin.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        other => other.unwrap(),
    }
}

/// The helper must accept a child that exits without reading its input.
/// 1 MiB is more than a pipe buffer, so the write always hits the closed
/// pipe; with a small input this only happens when the child is fast.
#[test]
fn run_accepts_a_child_that_does_not_read_its_input() {
    let out = run(&["--version"], &"x".repeat(1 << 20), &[]);
    assert_eq!(out.status.code(), Some(0));
}

/// `init` with the key file `.cd-key` inside the vault (the old layout,
/// which the other commands find without `--key-file`), unless `extra`
/// gives `--key-file`.
fn init(vault: &Path, password: &str, extra: &[&str]) -> Output {
    let in_vault = vault.join(".cd-key");
    let mut args = vec!["init", vault.to_str().unwrap(), "--new-password-fd", "0"];
    args.extend(FAST);
    if !extra.contains(&"--key-file") {
        args.extend(["--key-file", in_vault.to_str().unwrap()]);
    }
    args.extend(extra);
    run(&args, password, &[])
}

fn check(vault: &Path, password: &str, extra: &[&str]) -> Output {
    let mut args = vec!["check", vault.to_str().unwrap(), "--password-fd", "0"];
    args.extend(extra);
    run(&args, password, &[])
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// `RECOVERY KEY: ` plus 11 groups of 5 symbols of `0-9A-Z`.
fn key_from(o: &Output) -> String {
    let out = stdout(o);
    let key = out
        .strip_prefix("RECOVERY KEY: ")
        .and_then(|r| r.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("bad output: {out:?}"));
    let groups: Vec<&str> = key.split('-').collect();
    assert_eq!(groups.len(), 11);
    for g in groups {
        assert_eq!(g.len(), 5);
        assert!(
            g.bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        );
    }
    key.to_string()
}

#[test]
fn init_creates_vault_and_prints_key() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let out = init(&vault, "pw\n", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    key_from(&out);
    assert!(stderr(&out).contains("Write this recovery key down and keep it offline."));
    assert!(stderr(&out).contains("below the recommended defaults"));
    assert!(vault.join(".cd-vault").exists());
    assert!(vault.join(".cd-key").exists());
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(0));
}

#[test]
fn init_with_external_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let keys = dir.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let kf = keys.join("k");
    let out = init(&vault, "pw\n", &["--key-file", kf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!vault.join(".cd-key").exists());
    assert!(kf.exists());
    let out = check(&vault, "pw\n", &["--key-file", kf.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn init_into_non_empty_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x"), b"x").unwrap();
    let out = init(dir.path(), "pw\n", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("error: already exists"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn passwd_changes_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "old\n", &[]);
    let mut args = vec!["passwd", vault.to_str().unwrap(), "--new-password-fd", "0"];
    args.extend(FAST);
    let out = run(&args, "new\n", &[("CRYPTO_DRIVE_PASSWORD", "old")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = check(&vault, "old\n", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("wrong password or damaged key file"));
    assert_eq!(check(&vault, "new\n", &[]).status.code(), Some(0));
}

#[test]
fn recovery_key_matches_init() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let first = key_from(&init(&vault, "pw\n", &[]));
    let out = run(
        &[
            "recovery-key",
            vault.to_str().unwrap(),
            "--password-fd",
            "0",
        ],
        "pw\n",
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(key_from(&out), first);
}

#[test]
fn recover_needs_overwrite_and_sets_new_password() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let key = key_from(&init(&vault, "pw\n", &[]));
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();

    let mut args = vec!["recover", v, "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(&args, &key, &env);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("key file exists; use --overwrite to replace it"));
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(0));

    let mut args = vec!["recover", v, "--overwrite", "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(&args, &format!("{key}\n"), &env);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(check(&vault, "fresh\n", &[]).status.code(), Some(0));
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(2));
}

#[test]
fn recover_refuses_a_vault_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let key = key_from(&init(&vault, "pw\n", &[]));
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();
    // A mount or a rotation holds this lock.
    let lock = crypto_drive_core::vault::lock_vault(&vault).unwrap();
    let mut args = vec!["recover", v, "--overwrite", "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(&args, &format!("{key}\n"), &env);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("the vault is in use"),
        "{}",
        stderr(&out)
    );
    drop(lock);
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(0));
}

/// `mount` with an existing, empty mount point; no password is given, so a
/// password prompt would show up in the output.
fn mount_no_password(vault: &Path, mountpoint: &Path) -> Output {
    std::fs::create_dir_all(mountpoint).unwrap();
    run(
        &[
            "mount",
            vault.to_str().unwrap(),
            mountpoint.to_str().unwrap(),
        ],
        "",
        &[],
    )
}

#[test]
fn mount_of_a_missing_directory_says_how_to_create_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let out = mount_no_password(&vault, &dir.path().join("mnt"));
    assert_eq!(out.status.code(), Some(2));
    let v = vault.display();
    assert_eq!(
        stderr(&out),
        format!("error: {v} does not exist; create a vault with: crypto-drive init {v}\n")
    );
}

#[test]
fn mount_of_an_empty_directory_says_it_is_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    std::fs::create_dir(&vault).unwrap();
    let out = mount_no_password(&vault, &dir.path().join("mnt"));
    assert_eq!(out.status.code(), Some(2));
    let v = vault.display();
    assert_eq!(
        stderr(&out),
        format!(
            "error: {v} is not a crypto-drive vault (no .cd-vault file); create one with: crypto-drive init {v}\n"
        )
    );
}

#[test]
fn missing_key_file_says_how_to_find_it() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    std::fs::remove_file(vault.join(".cd-key")).unwrap();
    let want = "error: no key file given; pass it with --key-file (init printed its path; new key files are in ~/.crypto-drive/keys)\n";
    let out = mount_no_password(&vault, &dir.path().join("mnt"));
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stderr(&out), want);
    // The same check runs before the password in the other commands.
    let v = vault.to_str().unwrap();
    for args in [
        vec!["check", v],
        vec!["passwd", v],
        vec!["recovery-key", v],
        vec!["rotate-key", v, "--yes"],
    ] {
        let out = run(&args, "", &[]);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(stderr(&out), want, "{args:?}");
    }
}

#[test]
fn a_given_key_file_that_is_missing_says_how_to_recover() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    let key = dir.path().join("gone.cd-key");
    let out = run(
        &[
            "check",
            vault.to_str().unwrap(),
            "--key-file",
            key.to_str().unwrap(),
        ],
        "",
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        stderr(&out),
        format!(
            "error: key file {} not found; give the right --key-file, or write a new one with: crypto-drive recover {}\n",
            key.display(),
            vault.display()
        )
    );
}

/// The path after `Key file: ` in the output of init or recover.
fn printed_key_file(out: &Output) -> std::path::PathBuf {
    stderr(out)
        .lines()
        .find_map(|l| l.strip_prefix("Key file: "))
        .unwrap_or_else(|| panic!("no key file line: {}", stderr(out)))
        .into()
}

fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_without_key_file_writes_it_below_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let vault = dir.path().join("My Vault");
    let mut args = vec!["init", vault.to_str().unwrap(), "--new-password-fd", "0"];
    args.extend(FAST);
    let out = run(&args, "pw\n", &[("HOME", home.to_str().unwrap())]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    key_from(&out);
    assert!(
        stderr(&out).contains("Keep it safe and pass it with --key-file"),
        "{}",
        stderr(&out)
    );
    let key = printed_key_file(&out);
    let keys = home.join(".crypto-drive/keys");
    assert_eq!(key.parent(), Some(keys.as_path()));
    let name = key.file_name().unwrap().to_str().unwrap();
    let (stamp, rest) = name.split_at(17);
    assert!(stamp.chars().all(|c| c.is_ascii_digit()), "{name}");
    assert_eq!(rest, "_My_Vault.cd-key");
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&keys), 0o700);
    assert_eq!(mode(&home.join(".crypto-drive")), 0o700);
    // Nothing in the vault, so the key file is not synced with it.
    assert!(!vault.join(".cd-key").exists());
    let out = check(&vault, "pw\n", &["--key-file", key.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let out = check(&vault, "pw\n", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("no key file given"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn recover_without_key_file_writes_a_new_one_below_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    let vault = dir.path().join("v");
    let mut args = vec!["init", vault.to_str().unwrap(), "--new-password-fd", "0"];
    args.extend(FAST);
    let out = run(&args, "pw\n", &[("HOME", home.to_str().unwrap())]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let recovery = key_from(&out);
    let first = printed_key_file(&out);
    // The key file is lost; recover writes a new one with a new password.
    std::fs::remove_file(&first).unwrap();
    let mut args = vec!["recover", vault.to_str().unwrap(), "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(
        &args,
        &format!("{recovery}\n"),
        &[
            ("HOME", home.to_str().unwrap()),
            ("CRYPTO_DRIVE_NEW_PASSWORD", "fresh"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let second = printed_key_file(&out);
    assert_eq!(second.parent(), first.parent());
    assert_eq!(mode(&second), 0o600);
    let out = check(&vault, "fresh\n", &["--key-file", second.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn recover_of_an_empty_directory_says_it_is_no_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    std::fs::create_dir(&vault).unwrap();
    let out = run(&["recover", vault.to_str().unwrap()], "", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("is not a crypto-drive vault (no .cd-vault file)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn check_reports_foreign_entry() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    std::fs::write(vault.join(".DS_Store"), b"x").unwrap();
    let out = check(&vault, "pw\n", &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(stdout(&out), "warning: .DS_Store: foreign-entry\n");
}

#[test]
fn password_from_environment_warns() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    let out = run(
        &["check", vault.to_str().unwrap()],
        "",
        &[("CRYPTO_DRIVE_PASSWORD", "pw")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains(
        "warning: reading the password from CRYPTO_DRIVE_PASSWORD; other processes of the same user may see it"
    ));
}

#[test]
fn debug_level_from_rust_log_warns() {
    const WARNING: &str = "warning: debug logging shows clear file names";
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    let args = ["check", vault.to_str().unwrap(), "--password-fd", "0"];
    for (level, warns) in [
        ("debug", true),
        ("crypto_drive_core=trace", true),
        ("warn", false),
    ] {
        let out = run(&args, "pw\n", &[("RUST_LOG", level)]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(stderr(&out).contains(WARNING), warns, "RUST_LOG={level}");
    }
}

/// Runs the binary with no stdin at all, so a password prompt cannot succeed.
fn run_without_stdin(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crypto-drive"));
    cmd.args(args)
        .env_remove("CRYPTO_DRIVE_PASSWORD")
        .env_remove("CRYPTO_DRIVE_NEW_PASSWORD")
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// A vault `v` and an empty mount point `mnt` next to it.
fn vault_and_mountpoint() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let out = init(&vault, "pw\n", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let mnt = dir.path().join("mnt");
    std::fs::create_dir(&mnt).unwrap();
    (dir, vault, mnt)
}

#[test]
fn mount_inside_the_vault_fails_before_the_password() {
    let (_dir, vault, _mnt) = vault_and_mountpoint();
    let inner = vault.join("inner");
    std::fs::create_dir(&inner).unwrap();
    let out = run_without_stdin(
        &["mount", vault.to_str().unwrap(), inner.to_str().unwrap()],
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    assert!(
        err.contains(
            "error: the mount point must not be inside the vault, and the vault must not be inside the mount point"
        ),
        "{err}"
    );
    assert!(!err.contains("password"), "{err}");
}

#[test]
fn mount_with_wrong_password_fails() {
    let (_dir, vault, mnt) = vault_and_mountpoint();
    let out = run_without_stdin(
        &["mount", vault.to_str().unwrap(), mnt.to_str().unwrap()],
        &[("CRYPTO_DRIVE_PASSWORD", "wrong")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("error: wrong password or damaged key file"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn daemon_mount_with_wrong_password_reports_through_the_pipe() {
    let (_dir, vault, mnt) = vault_and_mountpoint();
    let out = run_without_stdin(
        &[
            "mount",
            "--daemon",
            vault.to_str().unwrap(),
            mnt.to_str().unwrap(),
        ],
        &[("CRYPTO_DRIVE_PASSWORD", "wrong")],
    );
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    // Only the parent prints the error.
    assert_eq!(
        err.matches("error: wrong password or damaged key file")
            .count(),
        1,
        "{err}"
    );
}

#[test]
fn mount_with_debug_warns_about_clear_names() {
    let (_dir, vault, mnt) = vault_and_mountpoint();
    let out = run_without_stdin(
        &[
            "mount",
            "--debug",
            vault.to_str().unwrap(),
            mnt.to_str().unwrap(),
        ],
        &[("CRYPTO_DRIVE_PASSWORD", "wrong")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("warning: debug logging shows clear file names"));
}

#[test]
fn unmount_of_a_plain_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_without_stdin(&["unmount", dir.path().to_str().unwrap()], &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).starts_with("error: "), "{}", stderr(&out));
}

#[test]
fn passwd_rejects_identical_fds() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    let mut args = vec!["passwd", vault.to_str().unwrap()];
    args.extend(["--password-fd", "0", "--new-password-fd", "0"]);
    args.extend(FAST);
    let out = run(&args, "pw\nnew\n", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--password-fd and --new-password-fd must differ"));
}

#[test]
fn init_with_pad_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain");
    let padded = dir.path().join("padded");
    assert_eq!(init(&plain, "pw\n", &[]).status.code(), Some(0));
    let out = init(&padded, "pw\n", &["--pad-sizes"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    // The flags byte is at offset 12, bit 0 is `pad_sizes`.
    let flags = |v: &Path| std::fs::read(v.join(".cd-vault")).unwrap()[12];
    assert_eq!(flags(&plain) & 1, 0);
    assert_eq!(flags(&padded) & 1, 1);
    assert_eq!(check(&padded, "pw\n", &[]).status.code(), Some(0));
}

fn rotate(vault: &Path, password: &str, extra: &[&str]) -> Output {
    let mut args = vec!["rotate-key", vault.to_str().unwrap(), "--password-fd", "0"];
    args.extend(FAST);
    args.extend(extra);
    run(&args, password, &[])
}

#[test]
fn rotate_key_needs_yes_without_tty() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "pw\n", &[]);
    let before = std::fs::read(vault.join(".cd-key")).unwrap();
    let out = rotate(&vault, "pw\n", &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("error: add --yes to confirm the key rotation"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("Do not use this vault on any other device"));
    assert_eq!(stdout(&out), "");
    assert_eq!(std::fs::read(vault.join(".cd-key")).unwrap(), before);
}

#[test]
fn rotate_key_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let old_key = key_from(&init(&vault, "pw\n", &[]));
    let out = rotate(&vault, "pw\n", &["--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let new_key = key_from(&out);
    assert_ne!(new_key, old_key);
    assert!(stderr(&out).contains(
        "Do not use this vault on any other device until the rotation has finished. Afterwards every device needs the new key file. Your sync client will upload the whole vault again."
    ));
    assert!(stderr(&out).contains("Keep the old recovery key until the rotation has finished."));
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(0));
    // recovery-key now shows the new key.
    let shown = run(
        &[
            "recovery-key",
            vault.to_str().unwrap(),
            "--password-fd",
            "0",
        ],
        "pw\n",
        &[],
    );
    assert_eq!(key_from(&shown), new_key);
    // The old recovery key is refused with the exact message.
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();
    let mut args = vec!["recover", v, "--overwrite", "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(&args, &old_key, &env);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains(
            "error: the recovery key does not belong to this vault, or it is from before the last key rotation\n"
        ),
        "{}",
        stderr(&out)
    );
    // The new one works.
    let out = run(&args, &new_key, &env);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(check(&vault, "fresh\n", &[]).status.code(), Some(0));
}

#[test]
fn passwd_keeps_key_set() {
    use crypto_drive_core::keyfile::{Argon2Params, KeyFile};
    use crypto_drive_core::rotate::{RotateOptions, rotate_key, set_fail_after_steps};

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    init(&vault, "old\n", &[]);
    // Stop the rotation at the marker write: the key file holds epochs 1 and 2.
    set_fail_after_steps(Some(2));
    let opts = RotateOptions {
        key_file: None,
        argon2: Some(Argon2Params {
            m_kib: 19456,
            t: 2,
            p: 1,
        }),
    };
    let res = rotate_key(&vault, b"old", &opts, &mut |_| {}, &mut |_| {});
    set_fail_after_steps(None);
    assert!(res.is_err());
    let epochs = |pw: &[u8]| {
        KeyFile::load(&vault.join(".cd-key"))
            .unwrap()
            .unlock(pw)
            .unwrap()
            .epochs()
            .to_vec()
    };
    assert_eq!(epochs(b"old"), vec![1, 2]);

    let mut args = vec!["passwd", vault.to_str().unwrap(), "--new-password-fd", "0"];
    args.extend(FAST);
    let out = run(&args, "new\n", &[("CRYPTO_DRIVE_PASSWORD", "old")]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(epochs(b"new"), vec![1, 2]);
}

/// Opens `path` as a descriptor that a child process inherits.
fn inherited_fd(path: &Path) -> std::os::fd::OwnedFd {
    nix::fcntl::open(
        path,
        nix::fcntl::OFlag::O_RDONLY,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap()
}

#[test]
fn recover_during_an_unfinished_rotation_needs_both_keys() {
    use std::os::fd::AsRawFd;

    let files = vec![("a.bin", vec![1u8; 10]), ("b.bin", vec![2u8; 70_000])];
    // Key file, then the three steps of the first file.
    let (dir, vault, old_key, new_key) = stopped_rotation(&[], &files, 4);
    let key_path = vault.join(".cd-key");
    let before = std::fs::read(&key_path).unwrap();
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();
    let mut args = vec!["recover", v, "--overwrite", "--recovery-key-fd", "0"];
    args.extend(FAST);
    // Only the old key: refused, nothing written.
    let out = run(&args, &old_key, &env);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains(
            "error: a key rotation is unfinished: give both recovery keys (old and new), or finish the rotation first\n"
        ),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), before);

    // A wrong second key: refused, nothing written.
    let wrong = dir.path().join("wrong");
    std::fs::write(&wrong, &old_key).unwrap();
    let fd = inherited_fd(&wrong);
    let fd_text = fd.as_raw_fd().to_string();
    let mut with_new = args.clone();
    with_new.extend(["--new-recovery-key-fd", fd_text.as_str()]);
    let out = run(&with_new, &old_key, &env);
    drop(fd);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains(
            "error: the new recovery key does not belong to the unfinished key rotation of this vault\n"
        ),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), before);

    // Both keys: the key set gets both epochs.
    let right = dir.path().join("right");
    std::fs::write(&right, &new_key).unwrap();
    let fd = inherited_fd(&right);
    let fd_text = fd.as_raw_fd().to_string();
    let mut with_new = args.clone();
    with_new.extend(["--new-recovery-key-fd", fd_text.as_str()]);
    let out = run(&with_new, &old_key, &env);
    drop(fd);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_files(&vault, b"fresh", &files, &[1, 2]);

    // The rotation finishes and all data reads.
    let out = rotate(&vault, "fresh\n", &["--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert_eq!(check(&vault, "fresh\n", &[]).status.code(), Some(0));
    assert_files(&vault, b"fresh", &files, &[2]);
}

/// Runs the binary with `stdin` on fd 0 and a stdout whose reader is gone
/// (a broken pipe).
fn run_with_closed_stdout(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crypto-drive"))
        .args(args)
        .env("HOME", test_home())
        .env_remove("CRYPTO_DRIVE_PASSWORD")
        .env_remove("CRYPTO_DRIVE_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    write_input(&mut child, stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn recovery_key_goes_to_stderr_if_stdout_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let key = vault.join(".cd-key");
    let mut args = vec![
        "init",
        vault.to_str().unwrap(),
        "--key-file",
        key.to_str().unwrap(),
        "--new-password-fd",
        "0",
    ];
    args.extend(FAST);
    let out = run_with_closed_stdout(&args, "pw\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("RECOVERY KEY: "), "{}", stderr(&out));

    let mut args = vec![
        "rotate-key",
        vault.to_str().unwrap(),
        "--password-fd",
        "0",
        "--yes",
    ];
    args.extend(FAST);
    let out = run_with_closed_stdout(&args, "pw\n");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("RECOVERY KEY: "), "{}", stderr(&out));
    assert_eq!(check(&vault, "pw\n", &[]).status.code(), Some(0));
}

/// A vault made by `init` (password "pw") with the directories `dirs`
/// and files `files`, and a rotation stopped after `steps` write steps.
/// Returns the temp dir, the vault, the old and the new recovery key.
fn stopped_rotation(
    dirs: &[&str],
    files: &[(&str, Vec<u8>)],
    steps: u64,
) -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    use crypto_drive_core::fs::{CryptoFs, VPath};
    use crypto_drive_core::rotate::{RotateOptions, rotate_key, set_fail_after_steps};
    use crypto_drive_core::vault::unlock_vault;

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v");
    let old_key = key_from(&init(&vault, "pw\n", &[]));
    let (v, _) = unlock_vault(&vault, None, b"pw").unwrap();
    let fs = CryptoFs::new(v).unwrap();
    for d in dirs {
        fs.mkdir(&VPath::parse(&format!("/{d}")).unwrap(), 0o755)
            .unwrap();
    }
    for (name, bytes) in files {
        let (_, h) = fs
            .create(&VPath::parse(&format!("/{name}")).unwrap(), 0o644)
            .unwrap();
        fs.write(h, 0, bytes).unwrap();
        fs.release(h).unwrap();
    }
    drop(fs);
    let mut new_key = String::new();
    set_fail_after_steps(Some(steps));
    let opts = RotateOptions {
        key_file: None,
        argon2: None,
    };
    let r = rotate_key(&vault, b"pw", &opts, &mut |_| {}, &mut |k| {
        new_key = k.to_owned()
    });
    set_fail_after_steps(None);
    assert!(r.is_err());
    assert!(!new_key.is_empty());
    (dir, vault, old_key, new_key)
}

/// All `files` read back with `password`, and the key set has `epochs`.
fn assert_files(vault: &Path, password: &[u8], files: &[(&str, Vec<u8>)], epochs: &[u32]) {
    use crypto_drive_core::fs::{CryptoFs, VPath};
    let (v, keys) = crypto_drive_core::vault::unlock_vault(vault, None, password).unwrap();
    assert_eq!(keys.epochs(), epochs);
    let fs = CryptoFs::new(v).unwrap();
    for (name, bytes) in files {
        let h = fs
            .open(&VPath::parse(&format!("/{name}")).unwrap(), false, false)
            .unwrap();
        assert_eq!(&fs.read(h, 0, 1 << 20).unwrap(), bytes);
        fs.release(h).unwrap();
    }
}

#[test]
fn recover_after_only_directory_renames_needs_both_keys() {
    use std::os::fd::AsRawFd;
    let files = vec![
        ("d1/in.txt", b"in d1".to_vec()),
        ("d2/in.txt", b"in d2".to_vec()),
    ];
    // Key file and the rename of one directory; no file was moved yet.
    let (dir, vault, old_key, new_key) = stopped_rotation(&["d1", "d2"], &files, 2);
    let key_path = vault.join(".cd-key");
    std::fs::remove_file(&key_path).unwrap();
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();
    let kp = key_path.to_str().unwrap();
    let mut args = vec!["recover", v, "--key-file", kp, "--recovery-key-fd", "0"];
    args.extend(FAST);
    let out = run(&args, &old_key, &env);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("error: a key rotation is unfinished"),
        "{}",
        stderr(&out)
    );
    assert!(!key_path.exists());

    let right = dir.path().join("right");
    std::fs::write(&right, &new_key).unwrap();
    let fd = inherited_fd(&right);
    let fd_text = fd.as_raw_fd().to_string();
    args.extend(["--new-recovery-key-fd", fd_text.as_str()]);
    let out = run(&args, &old_key, &env);
    drop(fd);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_files(&vault, b"fresh", &files, &[1, 2]);

    let out = rotate(&vault, "fresh\n", &["--yes"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(check(&vault, "fresh\n", &[]).status.code(), Some(0));
    assert_files(&vault, b"fresh", &files, &[2]);
}

#[test]
fn recover_after_a_crash_before_the_last_key_file_write_needs_only_the_new_key() {
    let files = vec![("a.bin", vec![1u8; 10]), ("b.bin", vec![2u8; 70_000])];
    // Key file, 3 steps per file, marker; the final key file write fails.
    let (_dir, vault, old_key, new_key) = stopped_rotation(&[], &files, 8);
    let env = [("CRYPTO_DRIVE_NEW_PASSWORD", "fresh")];
    let v = vault.to_str().unwrap();
    let mut args = vec!["recover", v, "--overwrite", "--recovery-key-fd", "0"];
    args.extend(FAST);
    // The marker is at the new epoch, so the old key is refused.
    let out = run(&args, &old_key, &env);
    assert_eq!(out.status.code(), Some(2));
    let out = run(&args, &new_key, &env);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(check(&vault, "fresh\n", &[]).status.code(), Some(0));
    assert_files(&vault, b"fresh", &files, &[2]);
}
