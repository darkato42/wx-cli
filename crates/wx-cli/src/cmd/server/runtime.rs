use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wx_paths::AppPaths;

use super::types::{ServerHealthPayload, ServerLaunchConfig, ServerRuntimeState, ServerSecrets};

pub struct ManagementLockGuard {
    lock_file: PathBuf,
}

impl Drop for ManagementLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_file);
    }
}

pub fn acquire_management_lock(
    ap: &AppPaths,
) -> Result<ManagementLockGuard, Box<dyn std::error::Error>> {
    ap.ensure_server_dirs()?;
    let lock_file = ap.server_lock_file();

    loop {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_file)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                return Ok(ManagementLockGuard { lock_file });
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let owner = fs::read_to_string(&lock_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                if owner.is_some_and(pid_is_running) {
                    return Err("another server management operation is in progress".into());
                }
                fs::remove_file(&lock_file)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

pub fn load_json<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, Box<dyn std::error::Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn load_runtime_state(
    ap: &AppPaths,
) -> Result<Option<ServerRuntimeState>, Box<dyn std::error::Error>> {
    load_json(&ap.server_state_file())
}

pub fn save_runtime_state(
    ap: &AppPaths,
    state: &ServerRuntimeState,
) -> Result<(), Box<dyn std::error::Error>> {
    save_json(&ap.server_state_file(), state)
}

/// Load the persisted launch config, re-attaching any secrets from the
/// separate 0600 secrets file. When the secrets file is absent (upgrade from
/// a version that stored secrets inline in config.json), falls back to the
/// legacy inline fields so restart/status do not lose the key/token.
pub fn load_launch_config(
    ap: &AppPaths,
) -> Result<Option<ServerLaunchConfig>, Box<dyn std::error::Error>> {
    let Some(mut config) = load_json::<ServerLaunchConfig>(&ap.server_config_file())? else {
        return Ok(None);
    };
    if let Some(secrets) = load_json::<ServerSecrets>(&ap.server_secrets_file())? {
        config.key = secrets.key;
        config.token = secrets.token;
    } else if let Some(legacy) = load_json::<LegacyLaunchConfig>(&ap.server_config_file())? {
        // Pre-secrets-file configs stored key/token inline. `#[serde(skip)]`
        // on ServerLaunchConfig ignores those fields during the normal
        // deserialize above, so read them explicitly here.
        config.key = legacy.key.or(config.key);
        config.token = legacy.token.or(config.token);
    }
    Ok(Some(config))
}

/// Deserialization shape for launch configs written by versions that stored
/// `key`/`token` inline in `config.json`. Used only as an upgrade fallback
/// when `secrets.json` is missing; modern configs carry no secret fields.
#[derive(Deserialize)]
struct LegacyLaunchConfig {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// Persist the launch config. `key` and `token` are serialization-skipped on
/// `ServerLaunchConfig`, so `config.json` holds no secrets; they are written to
/// a sibling `secrets.json` created with mode 0600 (owner read/write only).
pub fn save_launch_config(
    ap: &AppPaths,
    config: &ServerLaunchConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    save_json(&ap.server_config_file(), config)?;
    save_secrets_file(
        ap,
        &ServerSecrets {
            key: config.key.clone(),
            token: config.token.clone(),
        },
    )
}

/// Write the secrets file with restrictive permissions. The temp file is
/// created 0600 *before* writing so there is no 0644 window, and the final
/// file is chmodded 0600 after rename as belt-and-braces.
fn save_secrets_file(
    ap: &AppPaths,
    secrets: &ServerSecrets,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = ap.server_secrets_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp = path.with_extension("json.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(secrets)?)?;
        file.flush()?;
    }
    fs::rename(&temp, &path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn remove_runtime_state(ap: &AppPaths) -> Result<(), Box<dyn std::error::Error>> {
    match fs::remove_file(ap.server_state_file()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub fn pid_is_running(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn pid_matches_managed_worker(pid: u32, worker_id: &str) -> bool {
    process_command_line(pid)
        .map(|command| command.contains("server _worker") && command.contains(worker_id))
        .unwrap_or(false)
}

pub fn terminate_pid(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn process_command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let command = String::from_utf8(output.stdout).ok()?;
    let trimmed = command.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !pid_is_running(pid)
}

pub fn base_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

pub fn probe_health(
    base_url: &str,
    token: Option<&str>,
) -> Result<ServerHealthPayload, Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(250))
        .timeout_read(Duration::from_millis(750))
        .build();
    let url = format!("{}/api/v1/health", base_url.trim_end_matches('/'));
    let mut request = agent.get(&url);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call()?;
    Ok(response.into_json::<ServerHealthPayload>()?)
}

#[derive(Clone, Debug)]
pub struct RuntimeReporter {
    ap: AppPaths,
}

impl RuntimeReporter {
    pub fn new(ap: AppPaths, _config: ServerLaunchConfig) -> Self {
        Self { ap }
    }

    pub fn write_state(&self, state: ServerRuntimeState) -> Result<(), Box<dyn std::error::Error>> {
        save_runtime_state(&self.ap, &state)
    }

    pub fn clear_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        remove_runtime_state(&self.ap)
    }

    pub fn ap(&self) -> &AppPaths {
        &self.ap
    }
}
