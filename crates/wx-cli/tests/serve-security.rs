//! End-to-end coverage for the HTTP server's security posture.
//!
//! The worker is spawned with a real (minimal) encrypted fixture so the full
//! server pipeline — account resolution, DB open, middleware stack — actually
//! boots, unlike a bogus-data-dir harness. The fixture needs only
//! `db_storage/contact/contact.db` and `db_storage/session/session.db`
//! (SQLCipher-encrypted with TEST_KEY_HEX); message shards are optional.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use tempfile::TempDir;

const TEST_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";
const TEST_ACCOUNT_ID: &str = "wxid_test_account";
const TEST_TOKEN: &str = "test-token-abcdef0123456789";
const TALKER: &str = "wxid_alice";

static SERVER_START_LOCK: Mutex<()> = Mutex::new(());

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_wx-cli")
}

struct TestServer {
    _fixture: TempDir,
    child: Child,
    port: u16,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Raw HTTP response line + headers, since we need to inspect headers a normal
/// client would hide (and send a `Host` a normal client would not).
struct RawResponse {
    status: u16,
    raw: String,
}

impl RawResponse {
    fn header_present(&self, name: &str) -> bool {
        let needle = format!("\r\n{}:", name.to_ascii_lowercase());
        self.raw.to_ascii_lowercase().contains(&needle)
    }
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[test]
fn auth_is_enabled_by_default_without_explicit_token() {
    // Regression test for the core finding: previously, `server run` with no
    // --token disabled authentication entirely, so any local process (or any
    // web page in the user's browser) could read the whole message history.
    let server = spawn_server(&[]);
    let response = request(server.port, "/api/v1/health", &[("Host", "127.0.0.1")]);
    assert_eq!(
        response.status, 401,
        "server with no --token must NOT be unauthenticated: {}",
        response.raw
    );
}

#[test]
fn request_without_token_is_rejected() {
    let server = spawn_server(&["--token", TEST_TOKEN]);
    let response = request(server.port, "/api/v1/health", &[("Host", "127.0.0.1")]);
    assert_eq!(response.status, 401, "{}", response.raw);
}

#[test]
fn request_with_wrong_token_is_rejected() {
    let server = spawn_server(&["--token", TEST_TOKEN]);
    let response = request(
        server.port,
        "/api/v1/health",
        &[
            ("Host", "127.0.0.1"),
            ("Authorization", "Bearer not-the-right-token"),
        ],
    );
    assert_eq!(response.status, 401, "{}", response.raw);
}

#[test]
fn request_with_correct_token_is_accepted() {
    let server = spawn_server(&["--token", TEST_TOKEN]);
    let auth = format!("Bearer {TEST_TOKEN}");
    let response = request(
        server.port,
        "/api/v1/health",
        &[("Host", "127.0.0.1"), ("Authorization", &auth)],
    );
    assert_ne!(
        response.status, 401,
        "valid token must not be rejected: {}",
        response.raw
    );
}

#[test]
fn no_auth_flag_allows_unauthenticated_access() {
    // The escape hatch must still work for users who knowingly opt out.
    let server = spawn_server(&["--no-auth"]);
    let response = request(server.port, "/api/v1/health", &[("Host", "127.0.0.1")]);
    assert_ne!(response.status, 401, "{}", response.raw);
}

// ---------------------------------------------------------------------------
// DNS rebinding / Host guard
// ---------------------------------------------------------------------------

#[test]
fn rebound_host_header_is_rejected() {
    // A DNS-rebinding attacker resolves their own hostname to 127.0.0.1; the
    // victim's browser then sends that hostname in the Host header.
    let server = spawn_server(&["--no-auth"]);
    let response = request(
        server.port,
        "/api/v1/health",
        &[("Host", "attacker.example.com")],
    );
    assert_eq!(
        response.status, 403,
        "non-loopback Host must be rejected: {}",
        response.raw
    );
}

#[test]
fn loopback_host_header_is_accepted() {
    let server = spawn_server(&["--no-auth"]);
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let response = request(server.port, "/api/v1/health", &[("Host", host)]);
        assert_ne!(
            response.status, 403,
            "loopback host {host} must be accepted: {}",
            response.raw
        );
    }
}

#[test]
fn explicitly_allowed_host_is_accepted() {
    let server = spawn_server(&["--no-auth", "--allow-host", "wx.internal"]);
    let response = request(server.port, "/api/v1/health", &[("Host", "wx.internal")]);
    assert_ne!(response.status, 403, "{}", response.raw);
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

#[test]
fn cors_headers_absent_by_default() {
    // Regression test: the API used to run CorsLayer::permissive(), sending
    // `Access-Control-Allow-Origin: *`, which let ANY website the user visited
    // read their entire chat history cross-origin.
    let server = spawn_server(&["--no-auth"]);
    let response = request(
        server.port,
        "/api/v1/health",
        &[
            ("Host", "127.0.0.1"),
            ("Origin", "https://evil.example.com"),
        ],
    );
    assert!(
        !response.header_present("access-control-allow-origin"),
        "no ACAO header may be sent when CORS is not configured: {}",
        response.raw
    );
}

#[test]
fn configured_cors_origin_is_echoed() {
    let server = spawn_server(&["--no-auth", "--cors-origin", "http://localhost:5173"]);
    let response = request(
        server.port,
        "/api/v1/health",
        &[("Host", "127.0.0.1"), ("Origin", "http://localhost:5173")],
    );
    assert!(
        response.header_present("access-control-allow-origin"),
        "configured origin should receive CORS headers: {}",
        response.raw
    );
}

#[test]
fn unconfigured_origin_does_not_receive_cors_headers() {
    let server = spawn_server(&["--no-auth", "--cors-origin", "http://localhost:5173"]);
    let response = request(
        server.port,
        "/api/v1/health",
        &[
            ("Host", "127.0.0.1"),
            ("Origin", "https://evil.example.com"),
        ],
    );
    let raw = response.raw.to_ascii_lowercase();
    // The CORS layer is only installed when --cors-origin is configured, so an
    // unconfigured server must emit NO Access-Control-Allow-Origin header at
    // all. Asserting absence (not just non-echo) guards against regressions to
    // `Access-Control-Allow-Origin: *`.
    assert!(
        !raw.contains("access-control-allow-origin"),
        "unconfigured origins must receive no Access-Control-Allow-Origin header at all: {}",
        response.raw
    );
}

// ---------------------------------------------------------------------------
// Non-loopback bind still demands a token
// ---------------------------------------------------------------------------

#[test]
fn non_loopback_bind_without_token_is_refused() {
    let fixture = TempDir::new().expect("tempdir");
    let output = Command::new(bin())
        .args([
            "server",
            "_worker",
            "--data-dir",
            fixture.path().to_str().unwrap(),
            "--host",
            "0.0.0.0",
            "--port",
            "9199",
            "--runtime-root",
            fixture.path().join("runtime").to_str().unwrap(),
        ])
        .env("HOME", fixture.path())
        .output()
        .expect("run worker");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "should refuse to start: {stderr}");
    assert!(
        stderr.contains("--token is required"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn non_loopback_bind_cannot_be_waived_with_no_auth() {
    let fixture = TempDir::new().expect("tempdir");
    let output = Command::new(bin())
        .args([
            "server",
            "_worker",
            "--data-dir",
            fixture.path().to_str().unwrap(),
            "--host",
            "0.0.0.0",
            "--port",
            "9198",
            "--no-auth",
            "--runtime-root",
            fixture.path().join("runtime").to_str().unwrap(),
        ])
        .env("HOME", fixture.path())
        .output()
        .expect("run worker");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "--no-auth must not open a routable interface: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn spawn_server(extra_args: &[&str]) -> TestServer {
    let fixture = TempDir::new().expect("tempdir");
    create_minimal_fixture(fixture.path());
    let account_dir = fixture.path().join(TEST_ACCOUNT_ID);
    let runtime_root = fixture.path().join("runtime");

    let _guard = SERVER_START_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let port = find_open_port();

    let mut command = Command::new(bin());
    command
        .args([
            "server",
            "_worker",
            "--data-dir",
            account_dir.to_str().expect("account utf8"),
            "--key",
            TEST_KEY_HEX,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--poll",
            "--poll-ms",
            "1000",
            "--runtime-root",
            runtime_root.to_str().expect("runtime utf8"),
        ])
        .args(extra_args)
        .env("HOME", fixture.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = command.spawn().expect("spawn worker");
    wait_for_port(port);

    TestServer {
        _fixture: fixture,
        child,
        port,
    }
}

/// Create the minimal SQLCipher-encrypted dataset the server requires:
/// `db_storage/contact/contact.db` and `db_storage/session/session.db`.
/// Message shards are optional, so they are omitted.
fn create_minimal_fixture(root: &Path) {
    let account_dir = root.join(TEST_ACCOUNT_ID);
    let db_root = account_dir.join("db_storage");
    let contact_dir = db_root.join("contact");
    let session_dir = db_root.join("session");
    std::fs::create_dir_all(&contact_dir).expect("create contact dir");
    std::fs::create_dir_all(&session_dir).expect("create session dir");

    let raw_key = test_raw_key();
    create_encrypted_db(
        &contact_dir.join("contact.db"),
        &raw_key,
        "CREATE TABLE contact (
            username TEXT PRIMARY KEY,
            alias TEXT DEFAULT '',
            remark TEXT DEFAULT '',
            nick_name TEXT DEFAULT '',
            description TEXT DEFAULT NULL,
            extra_buffer BLOB DEFAULT NULL
        );",
        |conn| {
            conn.execute(
                "INSERT INTO contact (username, alias, remark, nick_name) VALUES (?1, ?2, ?3, ?4)",
                params![TALKER, "", "", "Alice"],
            )
            .expect("insert contact");
        },
    );
    create_encrypted_db(
        &session_dir.join("session.db"),
        &raw_key,
        "CREATE TABLE SessionTable (
            username TEXT,
            sort_timestamp INTEGER,
            summary TEXT
        );",
        |conn| {
            conn.execute(
                "INSERT INTO SessionTable VALUES (?1, ?2, ?3)",
                params![TALKER, 1_700_000_000_i64, "fixture summary"],
            )
            .expect("insert session");
        },
    );
}

fn test_raw_key() -> [u8; 32] {
    let bytes = hex::decode(TEST_KEY_HEX).expect("decode test key");
    let mut raw_key = [0_u8; 32];
    raw_key.copy_from_slice(&bytes);
    raw_key
}

fn create_encrypted_db(
    path: &Path,
    raw_key: &[u8; 32],
    schema_sql: &str,
    seed: impl FnOnce(&Connection),
) {
    let conn = Connection::open(path).expect("open sqlite");
    unsafe {
        let rc = rusqlite::ffi::sqlite3_key(
            conn.handle(),
            raw_key.as_ptr() as *const std::ffi::c_void,
            32,
        );
        assert_eq!(rc, 0, "sqlite3_key failed for {}", path.display());
    }
    conn.execute_batch(schema_sql).expect("apply schema");
    seed(&conn);
}

/// Wait until the port answers with an HTTP response. The health endpoint may
/// return 401 (auth on) — that still proves the middleware stack is live.
fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            );
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if buf.starts_with("HTTP/1.") {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start on port {port}");
}

/// Issue a raw HTTP/1.1 request so we can control the `Host` header exactly.
fn request(port: u16, path: &str, headers: &[(&str, &str)]) -> RawResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set timeout");

    let mut req = format!("GET {path} HTTP/1.1\r\n");
    let has_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
    if !has_host {
        req.push_str("Host: 127.0.0.1\r\n");
    }
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).expect("write request");

    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let raw = String::from_utf8_lossy(&bytes).to_string();

    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse status line from: {raw}"));

    RawResponse { status, raw }
}

fn find_open_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}
