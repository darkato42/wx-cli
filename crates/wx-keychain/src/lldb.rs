use std::process::Command;
use std::time::Duration;

use regex::Regex;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command as AsyncCommand;
use tokio::time::timeout;

use crate::error::KeychainError;
use crate::process::AccountDirInfo;
use crate::script::CAPTURE_KEY_SCRIPT;
use wx_decrypt::params::MACOS_4_1_7_31;
use wx_decrypt::validate_key;

/// Open a capture file for writing, refusing to write into an existing path.
///
/// `create_new` guarantees the file is fresh: a stale leftover is replaced by
/// the caller after removal, and a planted symlink/hardlink is never followed
/// (`O_EXCL` semantics — the link name is removed, not dereferenced). On Unix
/// the file is created 0600 and opened with O_NOFOLLOW; non-Unix targets get
/// the same atomic-write behaviour without permission bits.
fn open_write_0600(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            // Refuse to follow a symlink planted at the capture path (TOCTOU
            // defense on shared temp dirs).
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
    }
}

/// Whether the redacted LLDB transcript should be persisted.
///
/// Only the exact value `1` enables it: `WX_CLI_DEBUG_LLDB=0` (or any other
/// value) must not accidentally persist key-derived material.
fn debug_transcript_enabled() -> bool {
    std::env::var("WX_CLI_DEBUG_LLDB").is_ok_and(|v| v == "1")
}

/// Whether an open failure should be treated as "the name exists" and retried
/// after removing it: `AlreadyExists` (create_new on an existing path) or
/// `ELOOP` — with `O_NOFOLLOW`, a pre-existing symlink surfaces as ELOOP
/// rather than EEXIST, and the link name should be removed, never followed.
#[cfg(unix)]
fn is_stale_name(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists || err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_stale_name(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists
}

/// Refuse symlinked temp-dir components.
///
/// `ensure_dir`/`set_permissions` follow symlinks, so on a shared temp dir
/// another user could pre-create `$TMPDIR/wx-cli` (or a subdir) as a symlink
/// and redirect our permission changes and file creation to an unexpected
/// location. Fail closed instead of hardening through a link.
/// Atomically create-if-needed and tighten a directory to 0700, refusing to
/// follow a symlink at that exact path component. Unlike a check-then-act
/// pair (symlink check + `create_dir_all` + `set_permissions`), this
/// opens the directory with `O_NOFOLLOW | O_DIRECTORY` and calls `fchmod` on
/// the resulting file descriptor, so there is no window between the symlink
/// check and the permission change for another local user to swap the path
/// component and redirect the chmod/subsequent writes.
#[cfg(unix)]
fn create_and_secure_dir_atomic(dir: &std::path::Path) -> Result<(), KeychainError> {
    use std::os::unix::io::AsRawFd;

    // mkdir first (best-effort: may already exist, may race with another
    // process, may fail because a symlink occupies the name — all handled
    // by the O_NOFOLLOW open below, which is the actual security boundary).
    let _ = std::fs::create_dir(dir);

    let cpath = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(|_| {
        KeychainError::Other(format!("invalid path for capture dir: {}", dir.display()))
    })?;
    // SAFETY: cpath is a valid NUL-terminated C string for the duration of
    // the call; the returned fd is owned and closed via File's Drop.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(KeychainError::Other(format!(
            "could not open capture dir {} (symlink or missing): {err}",
            dir.display()
        )));
    }
    // SAFETY: fd is a just-opened, valid, owned file descriptor.
    let file = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
    // SAFETY: file.as_raw_fd() is valid for the duration of this call.
    let rc = unsafe { libc::fchmod(file.as_raw_fd(), 0o700) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(KeychainError::Other(format!(
            "could not secure capture dir {} to 0700: {err}",
            dir.display()
        )));
    }
    Ok(())
}

/// RAII guard: removes the capture script on every exit path, so an early
/// error (e.g. failing to spawn lldb, missing stdout/stderr pipes) cannot
/// leave the 0600 script behind. Also fires if the future is cancelled.
struct ScriptCleanup<'a>(&'a std::path::Path);

impl Drop for ScriptCleanup<'_> {
    fn drop(&mut self) {
        match std::fs::remove_file(self.0) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => eprintln!(
                "WARNING: could not remove LLDB capture script {}: {err}",
                self.0.display()
            ),
        }
    }
}

/// Persist the redacted LLDB transcript (WX_CLI_DEBUG_LLDB=1 only).
///
/// Returns an error instead of failing silently so the caller can report that
/// no transcript was actually produced.
fn write_redacted_transcript(
    output_path: &std::path::Path,
    redacted: &[String],
) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = match open_write_0600(output_path) {
        Ok(file) => file,
        Err(err) if is_stale_name(&err) => {
            // Stale transcript from an earlier debug run (or a planted link:
            // O_NOFOLLOW surfaces a pre-existing symlink as ELOOP): remove
            // the name and retry once.
            std::fs::remove_file(output_path)?;
            open_write_0600(output_path)?
        }
        Err(err) => return Err(err),
    };
    file.write_all(redacted.join("\n").as_bytes())
}

/// Result of a successful key capture.
#[derive(Debug)]
pub struct CaptureResult {
    pub raw_key: [u8; 32],
    pub call_count: u32,
    /// Which account directory the captured key belongs to.
    pub matched_account: AccountDirInfo,
}

/// Run the full LLDB key capture flow against all known account directories.
///
/// 1. Read salts from ALL account `message_0.db` files.
/// 2. Kill WeChat.
/// 3. Launch LLDB with `-w -n WeChat` (waits for WeChat to start).
/// 4. Open WeChat; user logs in.
/// 5. Stream LLDB output, parsing PBKDF2 calls.
/// 6. For each call with rounds=256000, check its salt against ALL known salts.
/// 7. On match, validate the full key via HMAC. Return key + matched account.
///
/// This approach never pre-picks a target account, so it works regardless of
/// which account WeChat decides to auto-login as.
pub async fn capture_key(
    accounts: &[AccountDirInfo],
    capture_timeout: Duration,
) -> Result<CaptureResult, KeychainError> {
    if accounts.is_empty() {
        return Err(KeychainError::Other(
            "no account directories provided".into(),
        ));
    }

    // Pre-read salts from all accounts. Skip unreadable DBs.
    let account_salts: Vec<([u8; 16], &AccountDirInfo)> = accounts
        .iter()
        .filter_map(|a| {
            wx_decrypt::read_db_salt(&a.message_db_path)
                .ok()
                .map(|salt| (salt, a))
        })
        .collect();

    if account_salts.is_empty() {
        return Err(KeychainError::Other(
            "could not read salt from any account database".into(),
        ));
    }

    // Kill WeChat.
    let _ = Command::new("killall").arg("WeChat").output();
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Write capture script to temp file. The script itself is not secret, but
    // it is written 0600 out of an abundance of caution and removed once the
    // capture finishes (see cleanup below).
    let script_path = wx_paths::AppPaths::lldb_script_file();
    if let Some(parent) = script_path.parent() {
        // Reject symlinked components before creating or tightening: another
        // user on a shared temp dir could pre-create the root (or the lldb
        // dir) as a symlink, redirecting our chmods and file creation. Both
        // components are secured atomically (open O_NOFOLLOW + fchmod on the
        // fd) rather than check-then-act, closing the TOCTOU window between
        // a symlink check and a path-based create_dir_all/set_permissions.
        #[cfg(unix)]
        {
            if let Some(root) = parent.parent() {
                create_and_secure_dir_atomic(root)?;
            }
            create_and_secure_dir_atomic(parent)?;
        }
        #[cfg(not(unix))]
        {
            wx_paths::AppPaths::ensure_dir(parent)?;
        }
    }
    // Guard lives at function scope for the WHOLE capture: it must be alive
    // when LLDB runs `command script import` (the script is consumed during
    // the session) and only remove the script on function exit/cancellation.
    // Placed before the write so an early failure (disk full, spawn error)
    // still cleans up.
    let _script_cleanup = ScriptCleanup(&script_path);
    {
        use std::io::Write;
        let mut file = match open_write_0600(&script_path) {
            Ok(file) => file,
            Err(err) if is_stale_name(&err) => {
                // Stale script from a crashed run (or a planted link: with
                // O_NOFOLLOW a pre-existing symlink surfaces as ELOOP).
                // Remove the name — never follow it — and retry once.
                std::fs::remove_file(&script_path)?;
                open_write_0600(&script_path)?
            }
            Err(err) => return Err(err.into()),
        };
        file.write_all(CAPTURE_KEY_SCRIPT.as_bytes())?;
    }

    // Prepare LLDB output file.
    let output_path = wx_paths::AppPaths::lldb_output_file();

    // Launch LLDB in wait mode.
    let mut lldb = AsyncCommand::new("lldb")
        .args([
            "-w",
            "-n",
            "WeChat",
            "-o",
            &format!("command script import {}", script_path.display()),
            "-o",
            "capture_keys",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| KeychainError::Other(format!("failed to start lldb: {e}")))?;

    // Brief pause then open WeChat.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = Command::new("open").arg("-a").arg("WeChat").output();

    eprintln!("Waiting for WeChat to start and trigger PBKDF2 calls...");
    eprintln!("Please log in to WeChat when prompted.");

    // Read LLDB stdout line by line, looking for PBKDF2 calls.
    let stdout = lldb
        .stdout
        .take()
        .ok_or_else(|| KeychainError::Other("no lldb stdout".into()))?;
    let mut reader = tokio::io::BufReader::new(stdout).lines();

    let re_header = Regex::new(r"^\[PBKDF2 #(\d+)\].*rounds=(\d+)").unwrap();
    let re_password = Regex::new(r"^\s*Password:\s*([0-9a-f]+)").unwrap();
    let re_salt = Regex::new(r"^\s*Salt:\s*([0-9a-f]+)").unwrap();

    let mut current_call: Option<(u32, u32)> = None; // (call_count, rounds)
    let mut current_password: Option<String> = None;
    let mut call_count = 0u32;
    let mut output_lines = Vec::new();

    let result = timeout(capture_timeout, async {
        loop {
            let line = match reader.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => break Err(KeychainError::NoPbkdfCalls),
                Err(e) => break Err(KeychainError::Other(format!("read error: {e}"))),
            };

            output_lines.push(line.clone());

            if let Some(caps) = re_header.captures(&line) {
                let count: u32 = caps[1].parse().unwrap_or(0);
                let rounds: u32 = caps[2].parse().unwrap_or(0);
                current_call = Some((count, rounds));
                current_password = None;
                call_count = count;
                continue;
            }

            if let Some(caps) = re_password.captures(&line) {
                current_password = Some(caps[1].to_string());
                continue;
            }

            if let Some(caps) = re_salt.captures(&line) {
                let salt_hex = caps[1].to_string();

                if let Some((_, rounds)) = current_call {
                    if rounds == 256000 {
                        if let Some(ref pwd_hex) = current_password {
                            if let Ok(salt_bytes) = hex::decode(&salt_hex) {
                                if salt_bytes.len() == 16 {
                                    let mut pbkdf_salt = [0u8; 16];
                                    pbkdf_salt.copy_from_slice(&salt_bytes);

                                    // Match against ALL known account salts.
                                    let mut matched: Option<CaptureResult> = None;
                                    'salt_match: for (known_salt, account) in &account_salts {
                                        if pbkdf_salt != *known_salt {
                                            continue;
                                        }
                                        // Salt matched — validate the key.
                                        if let Ok(key_bytes) = hex::decode(pwd_hex) {
                                            if key_bytes.len() == 32 {
                                                let mut raw_key = [0u8; 32];
                                                raw_key.copy_from_slice(&key_bytes);

                                                use std::io::Read;
                                                let mut first_page = vec![0u8; 4096];
                                                if let Ok(mut f) =
                                                    std::fs::File::open(&account.message_db_path)
                                                {
                                                    if f.read_exact(&mut first_page).is_ok()
                                                        && validate_key(
                                                            &first_page,
                                                            &raw_key,
                                                            &MACOS_4_1_7_31,
                                                        )
                                                        .is_some()
                                                    {
                                                        matched = Some(CaptureResult {
                                                            raw_key,
                                                            call_count,
                                                            matched_account: (*account).clone(),
                                                        });
                                                        break 'salt_match;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if let Some(result) = matched {
                                        break Ok(result);
                                    }
                                }
                            }
                        }
                    }
                }
                current_call = None;
                current_password = None;
            }
        }
    })
    .await;

    // Kill LLDB.
    let _ = lldb.kill().await;

    // The transcript contains the PBKDF2 password — i.e. the WeChat database
    // key — and its salt. By default we do NOT persist it at all. When
    // WX_CLI_DEBUG_LLDB=1 is set, a redacted copy (password/salt hex masked)
    // is written with mode 0600 for debugging; the raw values never hit disk.
    if debug_transcript_enabled() {
        let redacted = redact_sensitive_lines(&output_lines);
        // Same symlink rejection as the script path (defense in depth: the
        // shared dirs were already validated above, but the debug path must
        // never harden or write through a link either). If the dir cannot be
        // secured, skip the transcript entirely rather than write through a
        // potentially hostile path.
        let mut dir_secure = true;
        if let Some(parent) = output_path.parent() {
            #[cfg(unix)]
            {
                // Same atomic (open O_NOFOLLOW + fchmod) hardening as the
                // script path: no check-then-act window for another local
                // user to swap a path component with a symlink.
                if let Err(err) = create_and_secure_dir_atomic(parent) {
                    eprintln!("WARNING: {err} — skipping redacted LLDB transcript");
                    dir_secure = false;
                }
            }
            #[cfg(not(unix))]
            {
                if let Err(err) = wx_paths::AppPaths::ensure_dir(parent) {
                    eprintln!("WARNING: could not create {}: {err}", parent.display());
                }
            }
        }
        if dir_secure {
            match write_redacted_transcript(&output_path, &redacted) {
                Ok(()) => eprintln!(
                    "WX_CLI_DEBUG_LLDB set: redacted LLDB transcript written to {}",
                    output_path.display()
                ),
                Err(err) => eprintln!(
                    "WARNING: WX_CLI_DEBUG_LLDB set but could not write redacted transcript to {}: {err}",
                    output_path.display()
                ),
            }
        }
    } else if std::fs::symlink_metadata(&output_path).is_ok() {
        // Clean up transcripts (or dangling transcript symlinks) left by
        // older versions; symlink_metadata so the link itself is removed
        // even when its target no longer exists.
        if let Err(err) = std::fs::remove_file(&output_path) {
            eprintln!(
                "WARNING: could not remove leftover LLDB transcript {}: {err}",
                output_path.display()
            );
        }
    }

    // (The capture script is removed by ScriptCleanup on scope exit.)

    match result {
        Ok(inner) => inner,
        Err(_) => Err(KeychainError::CaptureTimeout {
            seconds: capture_timeout.as_secs(),
        }),
    }
}

/// Mask the secret payload of every `Password:` / `Salt:` line in an LLDB
/// transcript.
///
/// The transcript is the only persistent artifact of key capture and would
/// otherwise contain the WeChat database key (PBKDF2 password) and salt in
/// plaintext. Everything else — the lldb banner, breakpoint output, call
/// headers — is left intact so debug sessions stay useful.
///
/// Line shapes handled (matching the capture regexes):
///   `    Password: 4f3d...a1b2`  -> `    Password: <redacted>`
///   `    Salt: 8c01...7e`        -> `    Salt: <redacted>`
/// Lines that merely contain these words (e.g. error messages) are untouched
/// unless they start with optional whitespace followed by the exact keyword.
pub(crate) fn redact_sensitive_lines(lines: &[String]) -> Vec<String> {
    fn mask(line: &str, keyword: &str) -> Option<String> {
        let trimmed = line.trim_start();
        let rest = trimmed.strip_prefix(keyword)?;
        // Require "Keyword:" followed by whitespace and a hex payload so we
        // never mask prose like "Password prompt failed".
        if !rest.starts_with(':') {
            return None;
        }
        let after = &rest[1..];
        if !after.starts_with(char::is_whitespace) {
            return None;
        }
        let value = after.trim_start();
        if value.is_empty() || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let indent = &line[..line.len() - line.trim_start().len()];
        Some(format!("{indent}{keyword}: <redacted>"))
    }

    /// Defense in depth: if the LLDB output format drifts from the
    /// "Keyword: <hex>" shape (extra whitespace, changed case, wrapped
    /// values, stderr interleaving), a bare 32/64-hex token must still not
    /// survive in the retained transcript. Both the PBKDF2 password (64 hex)
    /// and salt (32 hex) are masked wherever they appear as standalone runs.
    /// Shorter hex runs (e.g. memory addresses) are left intact.
    fn mask_hex_tokens(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut hex_run = String::new();
        for ch in line.chars() {
            if ch.is_ascii_hexdigit() {
                hex_run.push(ch);
            } else {
                if hex_run.len() == 32 || hex_run.len() == 64 {
                    out.push_str("<redacted>");
                } else {
                    out.push_str(&hex_run);
                }
                hex_run.clear();
                out.push(ch);
            }
        }
        if hex_run.len() == 32 || hex_run.len() == 64 {
            out.push_str("<redacted>");
        } else {
            out.push_str(&hex_run);
        }
        out
    }

    /// True when `line` is nothing but hex digits and whitespace — the shape
    /// of a wrapped continuation of a Password:/Salt: value that doesn't
    /// happen to land on a clean 32/64-char boundary (e.g. wrapped as
    /// 40+24 hex chars across two lines).
    fn is_hex_only_continuation(line: &str) -> bool {
        let trimmed = line.trim();
        !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }

    // Track whether we just redacted a Password:/Salt: line so a following
    // hex-only continuation line (wrapped value) is masked outright, even
    // when its length isn't exactly 32 or 64 (defense-in-depth for format
    // drift beyond what mask_hex_tokens' fixed-length check covers).
    let mut expect_continuation = false;
    lines
        .iter()
        .map(|line| {
            if let Some(redacted) = mask(line, "Password").or_else(|| mask(line, "Salt")) {
                expect_continuation = true;
                return redacted;
            }
            if expect_continuation && is_hex_only_continuation(line) {
                let indent = &line[..line.len() - line.trim_start().len()];
                return format!("{indent}<redacted>");
            }
            expect_continuation = false;
            mask_hex_tokens(line)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_lines;

    fn lines(input: &[&str]) -> Vec<String> {
        input.iter().map(|s| s.to_string()).collect()
    }

    /// Serializes env-var mutation across parallel tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn symlinked_temp_dir_components_are_rejected() {
        use super::create_and_secure_dir_atomic;
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();

        // A real, not-yet-existing directory is created and tightened.
        let real_dir = tmp.path().join("real");
        assert!(create_and_secure_dir_atomic(&real_dir).is_ok());
        let mode = std::fs::metadata(&real_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        // An existing, permissive directory gets tightened too.
        let loose_dir = tmp.path().join("loose");
        std::fs::create_dir(&loose_dir).unwrap();
        std::fs::set_permissions(&loose_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(create_and_secure_dir_atomic(&loose_dir).is_ok());
        let mode = std::fs::metadata(&loose_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        // A symlinked name at the target path is refused: O_NOFOLLOW makes
        // the open fail, so the chmod is never reached and the symlink's
        // target is never touched — no check-then-act window.
        let real_target = tmp.path().join("target");
        std::fs::create_dir(&real_target).unwrap();
        std::fs::set_permissions(&real_target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_target, &link).unwrap();
        let err = create_and_secure_dir_atomic(&link).unwrap_err();
        assert!(err.to_string().contains("symlink or missing"), "{err}");
        // The symlink target must be untouched (still 0755, not 0700).
        let mode = std::fs::metadata(&real_target)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn debug_transcript_requires_exact_value_1() {
        use super::debug_transcript_enabled;
        let _guard = ENV_LOCK.lock().unwrap();
        // Restore the previous value (or absence) so other tests are not
        // affected by this one's mutation of the process-wide environment.
        let previous = std::env::var("WX_CLI_DEBUG_LLDB").ok();
        std::env::set_var("WX_CLI_DEBUG_LLDB", "1");
        assert!(debug_transcript_enabled());
        for off in ["0", "true", "yes", ""] {
            std::env::set_var("WX_CLI_DEBUG_LLDB", off);
            assert!(!debug_transcript_enabled(), "{off:?} must not enable it");
        }
        match previous {
            Some(value) => std::env::set_var("WX_CLI_DEBUG_LLDB", value),
            None => std::env::remove_var("WX_CLI_DEBUG_LLDB"),
        }
    }

    #[test]
    fn password_and_salt_hex_are_masked() {
        let input = lines(&[
            "[PBKDF2 #1] rounds=256000",
            "    Password: 4f3daabbccddeeff00112233445566778899aabbccddeeff0011223344556677",
            "    Salt: 8c01fe7a",
            "done",
        ]);
        let out = redact_sensitive_lines(&input);
        assert_eq!(out[0], "[PBKDF2 #1] rounds=256000");
        assert_eq!(out[1], "    Password: <redacted>");
        assert_eq!(out[2], "    Salt: <redacted>");
        assert_eq!(out[3], "done");
        // The raw hex values must not survive anywhere.
        let joined = out.join("\n");
        assert!(!joined.contains("4f3daabb"));
        assert!(!joined.contains("8c01fe7a"));
    }

    #[test]
    fn wrapped_password_continuation_is_masked() {
        // Simulates a value wrapped mid-hex-run across two lines by an lldb
        // format change: neither half is exactly 32 or 64 hex chars, so
        // mask_hex_tokens alone would miss it, but it directly follows a
        // Password: line so the continuation guard catches it.
        let input = lines(&[
            "    Password: 4f3daabbccddeeff0011223344556677889",
            "9aabbccddeeff0011223344556677",
            "done",
        ]);
        let out = redact_sensitive_lines(&input);
        assert_eq!(out[0], "    Password: <redacted>");
        assert_eq!(out[1], "<redacted>");
        assert_eq!(out[2], "done");
        let joined = out.join("\n");
        assert!(!joined.contains("4f3daabb"));
        assert!(!joined.contains("9aabbccd"));
    }

    #[test]
    fn drifted_format_hex_tokens_are_still_masked() {
        // Format drift (wrapped value, no keyword, case change) must not let
        // a 32/64-hex secret survive the redactor.
        let password = "4f3daabbccddeeff00112233445566778899aabbccddeeff0011223344556677";
        let salt = "8c01fe7a1234567890abcdef12345678";
        let input = lines(&[
            &format!("Password = {password}"),       // keyword shape changed
            &format!("    salt: {salt}"),            // lowercase keyword
            &format!("interleaved {password} here"), // bare token mid-line
            "frame #0: 0x0000000100003f50",          // 16-hex address: must NOT mask
            "done",
        ]);
        let out = redact_sensitive_lines(&input);
        let joined = out.join("\n");
        assert!(!joined.contains(&password[..16]), "{joined}");
        assert!(!joined.contains(&salt[..16]), "{joined}");
        assert!(joined.contains("0x0000000100003f50"), "{joined}");
        assert!(joined.contains("done"), "{joined}");
    }

    #[test]
    fn indentation_is_preserved() {
        let input = lines(&["  Password: deadbeef"]);
        let out = redact_sensitive_lines(&input);
        assert_eq!(out[0], "  Password: <redacted>");
    }

    #[test]
    fn prose_mentioning_keywords_is_not_masked() {
        let input = lines(&[
            "Password prompt failed: not a hex payload",
            "Salt:  not-hex",
            "Salt: 12ab!",
            "error: Salt: has colon but bad value",
        ]);
        let out = redact_sensitive_lines(&input);
        assert_eq!(out, input, "non-hex lines must pass through unchanged");
    }

    #[test]
    fn empty_and_short_lines_are_untouched() {
        let input = lines(&["", "   ", "Password:", "Salt:"]);
        let out = redact_sensitive_lines(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn long_transcript_masks_all_calls() {
        let mut input = Vec::new();
        for i in 0..3 {
            input.push(format!("[PBKDF2 #{i}] rounds=256000"));
            input.push(format!("    Password: {:064x}", i));
            input.push(format!("    Salt: {:032x}", i + 1));
        }
        let out = redact_sensitive_lines(&input);
        for line in &out {
            if line.contains("Password:") || line.contains("Salt:") {
                assert!(line.ends_with("<redacted>"), "{line}");
            }
        }
    }
}
