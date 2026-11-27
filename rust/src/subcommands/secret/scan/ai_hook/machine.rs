//! Machine and user identity sent with every scan, from which the server lists the
//! machine on the Endpoints page. Mirrors `ggshield/core/machine_id.py` and
//! `ScanContext.get_http_headers()` value for value: the server joins hook scans
//! and Python scans on the machine id.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ureq::http::HeaderValue;

/// Bounds the system-id subprocesses, so a hung WMI service cannot freeze the hook.
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// A legitimate fallback cache holds one UUID line.
const CACHE_READ_MAX: u64 = 65536;

/// `running_on_ci()` and `SupportedCI.from_ci_env()`.
const CI_ENV_VARS: [&str; 14] = [
    "CI",
    "CODEBUILD_BUILD_ID",
    "TEAMCITY_VERSION",
    "bamboo_buildNumber",
    "GITLAB_CI",
    "GITHUB_ACTIONS",
    "TRAVIS",
    "JENKINS_HOME",
    "JENKINS_URL",
    "CIRCLECI",
    "BITBUCKET_COMMIT",
    "HARNESS_BUILD_ID",
    "DRONE",
    "BUILD_BUILDID",
];

/// Placeholder SMBIOS UUIDs from unconfigured or cloned firmware: they identify
/// an image, not a machine. Same list as Python's `_SENTINEL_UUID_HEX`.
#[cfg_attr(not(windows), allow(dead_code))]
const SENTINEL_UUID_HEX: [&str; 6] = [
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "03000200040005000006000700080009",
    "030201000504070608090a0b0c0d0e0f",
    "10000000000080000040000000000000",
    "fefefefefefefefefefefefefefefefe",
];

pub type Header = (&'static str, HeaderValue);

/// The `session_id` of `_WARM_UP_EVENT` in ggshield/verticals/ai/installation.py.
const SETUP_WARM_UP_SESSION_ID: &str = "ggshield-machine-setup";

/// `machine setup` runs its warm-up event through the hook: no agent ran it, so it
/// must not tell the server this machine's agent has hooks installed.
pub fn is_setup_warm_up(raw: &serde_json::Value) -> bool {
    raw.get("session_id").and_then(serde_json::Value::as_str) == Some(SETUP_WARM_UP_SESSION_ID)
}

/// The `GGShield-Machine-*` headers. The server reads them as latin-1, so a value
/// latin-1 cannot hold is left out rather than sent mangled.
pub fn headers(config_opt_out: bool) -> Vec<Header> {
    #[cfg(test)]
    HEADERS_BUILT.with(|built| built.set(built.get() + 1));
    let mut values = vec![
        ("GGShield-Machine-Id", machine_id().to_string()),
        ("GGShield-Machine-Username", username()),
    ];
    if sends_hostname(config_opt_out, env_is_set) {
        values.push(("GGShield-Machine-Hostname", hostname()));
    }
    values
        .into_iter()
        .filter_map(|(name, value)| Some((name, latin1_header(&value)?)))
        .collect()
}

#[cfg(test)]
thread_local! {
    /// How many times this thread built the headers, for the tests.
    pub static HEADERS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn latin1_header(value: &str) -> Option<HeaderValue> {
    let bytes: Option<Vec<u8>> = value
        .chars()
        .map(|c| u8::try_from(u32::from(c)).ok())
        .collect();
    HeaderValue::from_bytes(&bytes?).ok()
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// `endpoint_registration_opt_out()` and `running_on_ci()`: a CI runner is not an
/// endpoint, and the server registers hook users from the hostname.
fn sends_hostname(config_opt_out: bool, is_set: impl Fn(&str) -> bool) -> bool {
    !config_opt_out
        && !is_set("GGSHIELD_NO_ENDPOINT_REGISTRATION")
        && !CI_ENV_VARS.iter().any(|name| is_set(name))
}

/// `getpass.getuser()`.
fn username() -> String {
    ["LOGNAME", "USER", "LNAME", "USERNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
        .or_else(passwd_name)
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(unix)]
fn passwd_name() -> Option<String> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result = std::ptr::null_mut();
    // SAFETY: every buffer is passed with its own length; `result` is only
    // dereferenced when the call reports success.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success `pw_name` is a NUL-terminated string inside `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr((*result).pw_name) };
    Some(name.to_string_lossy().into_owned()).filter(|n| !n.is_empty())
}

/// `os.getlogin()`, Python's fallback when no variable names the user.
#[cfg(windows)]
fn passwd_name() -> Option<String> {
    use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;
    let mut buf = [0u16; 257];
    let mut len = buf.len() as u32;
    // SAFETY: `len` is the buffer's length in UTF-16 units, as the API expects.
    if unsafe { GetUserNameW(buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }
    // `len` counts the terminating NUL.
    let name = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
    Some(name).filter(|n| !n.is_empty())
}

#[cfg(not(any(unix, windows)))]
fn passwd_name() -> Option<String> {
    None
}

/// `_get_hostname()`.
fn hostname() -> String {
    #[cfg(windows)]
    if let Some(name) = std::env::var("COMPUTERNAME")
        .ok()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
    {
        return name;
    }
    system_hostname().unwrap_or_else(|| "unknown".into())
}

#[cfg(unix)]
fn system_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the length passed is the buffer's.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned()).filter(|n| !n.is_empty())
}

/// `socket.gethostname()`, which CPython reads with this same call on Windows.
#[cfg(windows)]
fn system_hostname() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    };
    let mut buf = [0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: `len` is the buffer's length in UTF-16 units, as the API expects.
    if unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &mut len) }
        == 0
    {
        return None;
    }
    // On success `len` excludes the terminating NUL.
    Some(String::from_utf16_lossy(&buf[..len as usize])).filter(|n| !n.is_empty())
}

#[cfg(not(any(unix, windows)))]
fn system_hostname() -> Option<String> {
    None
}

/// `_get_machine_id()`.
fn machine_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(resolve_machine_id)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn resolve_machine_id() -> String {
    system_id().unwrap_or_else(fallback_id)
}

/// `ioreg` takes about 18 ms and `wmic` can take seconds, so the resolved id is
/// kept in the cache dir, fallback included: a failed lookup is not retried on
/// every event. It is resolved again once a day, so a reimaged or cloned machine
/// soon reports the same id as Python, which resolves it on every run.
#[cfg(any(target_os = "macos", windows))]
fn resolve_machine_id() -> String {
    let cache = crate::subcommands::secret::scan::ai_hook::config::cache_dir()
        .map(|dir| dir.join("machine_id"));
    cached_for_a_day(cache.as_deref(), || system_id().unwrap_or_else(fallback_id))
}

#[cfg(target_os = "linux")]
fn system_id() -> Option<String> {
    [
        "/etc/machine-id",
        "/sys/class/dmi/id/product_uuid",
        "/var/lib/dbus/machine-id",
    ]
    .iter()
    .find_map(|path| first_nonempty_line(&std::fs::read(path).ok()?))
}

/// The id cached at `path` if fresh, otherwise `resolve()`'s, cached.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn cached_for_a_day(path: Option<&Path>, resolve: impl FnOnce() -> String) -> String {
    if let Some(id) = path.and_then(read_fresh_cache) {
        return id;
    }
    let id = resolve();
    if let Some(path) = path
        && path.parent().is_some_and(|dir| {
            crate::subcommands::secret::scan::ai_hook::secure_file::create_dir_private(dir).is_ok()
        })
    {
        let _ = crate::subcommands::secret::scan::ai_hook::secure_file::write_private(path, &id);
    }
    id
}

const SYSTEM_ID_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The cached id, unless it is older than `SYSTEM_ID_CACHE_TTL` or dated in the
/// future.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn read_fresh_cache(path: &Path) -> Option<String> {
    let age = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()?;
    if age > SYSTEM_ID_CACHE_TTL {
        return None;
    }
    first_nonempty_line(
        crate::subcommands::secret::scan::ai_hook::secure_file::read_if_trusted(path)?.as_bytes(),
    )
}

#[cfg(target_os = "macos")]
fn system_id() -> Option<String> {
    let stdout = run_with_timeout(Command::new("/usr/sbin/ioreg").args([
        "-rd1",
        "-c",
        "IOPlatformExpertDevice",
    ]))?;
    let re = regex::Regex::new(r#""IOPlatformUUID"\s*=\s*"([^"]+)""#).ok()?;
    Some(re.captures(&stdout)?[1].trim().to_string()).filter(|id| !id.is_empty())
}

/// Binaries are resolved from `%SystemRoot%`: by bare name, `CreateProcess` would
/// run one planted in the current directory first.
#[cfg(windows)]
fn system_id() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let root = PathBuf::from(
        std::env::var("SystemRoot")
            .ok()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| r"C:\Windows".into()),
    );
    let wmic = root.join(r"System32\wbem\WMIC.exe");
    if let Some(id) = run_with_timeout(
        Command::new(wmic)
            .args(["csproduct", "get", "uuid"])
            .creation_flags(CREATE_NO_WINDOW),
    )
    .and_then(|out| parse_wmic_uuid(&out))
    {
        return Some(id);
    }
    let powershell = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    run_with_timeout(
        Command::new(powershell)
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ])
            .creation_flags(CREATE_NO_WINDOW),
    )
    .and_then(|out| normalize_uuid(out.trim()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn system_id() -> Option<String> {
    None
}

/// Stdout of a command that exits successfully within `SUBPROCESS_TIMEOUT`.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn run_with_timeout(command: &mut Command) -> Option<String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    // Drained on its own thread, so a full pipe cannot stall the child.
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).map(|_| out)
    });
    let deadline = Instant::now() + SUBPROCESS_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().ok()?.ok()?;
                return status
                    .success()
                    .then(|| String::from_utf8_lossy(&out).into_owned());
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// `_normalize_uuid()`: lowercase dashed form of exactly 32 hex digits, braces,
/// `urn:`/`uuid:` and dashes stripped; sentinels rejected.
#[cfg_attr(not(windows), allow(dead_code))]
fn normalize_uuid(value: &str) -> Option<String> {
    let stripped = value.trim().replace("urn:", "").replace("uuid:", "");
    let hex = stripped
        .trim_matches(|c| c == '{' || c == '}')
        .replace('-', "");
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    if SENTINEL_UUID_HEX.contains(&hex.as_str()) {
        return None;
    }
    Some(dashed(&hex))
}

/// `_parse_wmic_uuid()`: the first line, past the `UUID` header, that normalizes.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_wmic_uuid(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.eq_ignore_ascii_case("UUID"))
        .find_map(normalize_uuid)
}

fn dashed(hex: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn first_nonempty_line(data: &[u8]) -> Option<String> {
    String::from_utf8_lossy(data)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

/// `_machine_id_cache_path()`: shared with Python and satori, so a machine with
/// no hardware id converges on one id across the three.
fn fallback_path() -> Option<PathBuf> {
    Some(
        crate::subcommands::secret::scan::ai_hook::user_config::home_dir()?
            .join(".ggshield")
            .join("machine_id"),
    )
}

fn fallback_id() -> String {
    let Some(path) = fallback_path() else {
        return mint_uuid();
    };
    if let Some(id) = read_trusted_cache_line(&path) {
        return id;
    }
    let id = mint_uuid();
    let _ = write_fallback(&path, &id);
    id
}

/// `uuid.uuid4()`. Not a secret, only unique: sha256 over the time, the pid and
/// std's `RandomState`, which is keyed from the OS random source.
fn mint_uuid() -> String {
    use std::hash::BuildHasher;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let random = std::collections::hash_map::RandomState::new().hash_one(nanos);
    let digest = crate::subcommands::secret::scan::ai_hook::hash::sha256_hex(&format!(
        "{nanos}:{}:{random}",
        std::process::id()
    ));
    let mut hex: Vec<char> = digest.chars().take(32).collect();
    hex[12] = '4';
    hex[16] = ['8', '9', 'a', 'b'][hex[16].to_digit(16).unwrap_or(0) as usize & 3];
    dashed(&hex.into_iter().collect::<String>())
}

/// `_is_trusted_cache_owner()`: no *other* unprivileged user may plant the id.
#[cfg_attr(not(unix), allow(dead_code))]
fn is_trusted_owner(file_uid: u32, euid: u32, home_uid: Option<u32>) -> bool {
    file_uid == euid || file_uid == 0 || Some(file_uid) == home_uid
}

/// `_read_trusted_cache_line()`, checked on the open descriptor.
fn read_trusted_cache_line(path: &Path) -> Option<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK: a planted FIFO must not block the hook.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return None;
        }
        let home_uid = path
            .parent()
            .and_then(Path::parent)
            .and_then(|home| std::fs::metadata(home).ok())
            .map(|m| m.uid());
        // SAFETY: `geteuid` is a plain syscall wrapper and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !is_trusted_owner(meta.uid(), euid, home_uid) {
            return None;
        }
    }
    let mut data = Vec::new();
    file.take(CACHE_READ_MAX).read_to_end(&mut data).ok()?;
    first_nonempty_line(&data)
}

/// `_write_machine_id_cache()`: 0644 so a root run can adopt the id, never through
/// an existing path, and never over another user's file.
fn write_fallback(path: &Path, id: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        crate::subcommands::secret::scan::ai_hook::secure_file::create_dir_private(dir)?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: `geteuid` is a plain syscall wrapper and cannot fail.
            if meta.uid() != unsafe { libc::geteuid() } {
                return Ok(());
            }
        }
        #[cfg(not(unix))]
        let _ = meta;
        std::fs::remove_file(path)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        // The creation mode goes through the umask.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    file.write_all(format!("{id}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GIVEN names latin-1 can hold, one it cannot, and a control character
    /// WHEN they are turned into header values
    /// THEN `Clément` is sent as latin-1 bytes, the others are left out.
    #[test]
    fn header_values_are_latin1_or_left_out() {
        assert_eq!(
            latin1_header("Clément").expect("latin-1").as_bytes(),
            b"Cl\xe9ment"
        );
        assert!(latin1_header("Łukasz").is_none());
        assert!(latin1_header("a\nb").is_none());
    }

    /// GIVEN no opt-out, a config opt-out, the env opt-out, or any CI variable
    /// WHEN deciding whether to send the hostname
    /// THEN only the first sends it, as `ScanContext.get_http_headers()` does.
    #[test]
    fn the_hostname_is_skipped_on_ci_or_when_opted_out() {
        assert!(sends_hostname(false, |_| false));
        assert!(!sends_hostname(true, |_| false));
        assert!(!sends_hostname(false, |name| name == "GGSHIELD_NO_ENDPOINT_REGISTRATION"));
        for ci in CI_ENV_VARS {
            assert!(!sends_hostname(false, |name| name == ci), "{ci}");
        }
    }

    /// GIVEN the forms `wmic` and PowerShell print a UUID in
    /// WHEN they are normalized
    /// THEN they give Python's lowercase dashed form, and sentinels or junk give none.
    #[test]
    fn uuids_normalize_like_python() {
        let expected = Some("4c4c4544-0044-4810-8057-b5c04f4a5331".to_string());
        assert_eq!(
            normalize_uuid("4C4C4544-0044-4810-8057-B5C04F4A5331"),
            expected
        );
        assert_eq!(
            normalize_uuid("{4C4C4544-0044-4810-8057-B5C04F4A5331}"),
            expected
        );
        assert_eq!(
            normalize_uuid("urn:uuid:4C4C4544004448108057B5C04F4A5331"),
            expected
        );
        assert_eq!(normalize_uuid("FEFEFEFE-FEFE-FEFE-FEFE-FEFEFEFEFEFE"), None);
        assert_eq!(normalize_uuid("00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(normalize_uuid("4g4c4544-0044-4810-8057-b5c04f4a5331"), None);
        assert_eq!(
            parse_wmic_uuid("UUID\r\r\n4C4C4544-0044-4810-8057-B5C04F4A5331\r\r\n"),
            expected
        );
        assert_eq!(parse_wmic_uuid("UUID\n"), None);
    }

    /// GIVEN fresh fallback ids
    /// WHEN they are minted
    /// THEN each is a distinct, lowercase, dashed v4 UUID like `uuid.uuid4()`.
    #[test]
    fn minted_ids_are_distinct_v4_uuids() {
        let first = mint_uuid();
        let second = mint_uuid();
        assert_ne!(first, second);
        let re = regex::Regex::new(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        .expect("regex");
        assert!(re.is_match(&first), "{first}");
        assert!(re.is_match(&second), "{second}");
    }

    /// GIVEN no fallback id yet
    /// WHEN one is written and read back
    /// THEN the same id comes back, from a 0644 file in the shared location.
    #[test]
    fn a_written_fallback_id_reads_back() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join(".ggshield").join("machine_id");
        write_fallback(&path, "1234").expect("write");
        assert_eq!(read_trusted_cache_line(&path).as_deref(), Some("1234"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o644);
        }
        write_fallback(&path, "5678").expect("rewrite");
        assert_eq!(read_trusted_cache_line(&path).as_deref(), Some("5678"));
    }

    /// GIVEN a group-writable fallback file, or a symlink to one
    /// WHEN it is read
    /// THEN it is refused: another user could have planted it.
    #[cfg(unix)]
    #[test]
    fn a_loose_or_linked_fallback_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("machine_id");
        std::fs::write(&path, "planted\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).expect("chmod");
        assert_eq!(read_trusted_cache_line(&path), None);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let link = home.path().join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert_eq!(read_trusted_cache_line(&link), None);
        assert_eq!(read_trusted_cache_line(&path).as_deref(), Some("planted"));
    }

    /// GIVEN a cached hardware id written now, and one last written two days ago
    /// WHEN the cache is read
    /// THEN the fresh one is used and the stale one is read again from the system.
    #[test]
    fn a_cached_system_id_expires_after_a_day() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("machine_id");
        crate::subcommands::secret::scan::ai_hook::secure_file::write_private(&path, "4c4c4544\n")
            .expect("write");
        assert_eq!(read_fresh_cache(&path).as_deref(), Some("4c4c4544"));

        let two_days_ago = std::time::SystemTime::now() - 2 * SYSTEM_ID_CACHE_TTL;
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(two_days_ago))
            .expect("backdate");
        assert_eq!(read_fresh_cache(&path), None);
    }

    /// GIVEN a hardware id lookup that fails, so the fallback id is used
    /// WHEN the id is resolved twice
    /// THEN the second answer comes from the cache, without a second lookup.
    #[test]
    fn a_resolved_id_is_cached_even_when_it_is_the_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache").join("machine_id");
        let lookups = std::cell::Cell::new(0);
        let resolve = || {
            lookups.set(lookups.get() + 1);
            "fallback-id".to_string()
        };
        assert_eq!(cached_for_a_day(Some(&path), resolve), "fallback-id");
        assert_eq!(cached_for_a_day(Some(&path), resolve), "fallback-id");
        assert_eq!(lookups.get(), 1);
    }

    /// GIVEN the owner of a fallback file
    /// WHEN deciding whether to trust it
    /// THEN the current user, root and the home's owner are trusted, nobody else.
    #[test]
    fn only_us_root_or_the_home_owner_own_a_trusted_file() {
        assert!(is_trusted_owner(501, 501, None));
        assert!(is_trusted_owner(0, 501, None));
        assert!(is_trusted_owner(502, 0, Some(502)));
        assert!(!is_trusted_owner(502, 501, Some(501)));
    }

    /// GIVEN this machine
    /// WHEN the headers are built twice
    /// THEN a non-empty machine id and username are sent, the same both times.
    #[test]
    fn identity_headers_are_stable_within_a_run() {
        let first = headers(true);
        let names: Vec<_> = first.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, ["GGShield-Machine-Id", "GGShield-Machine-Username"]);
        assert!(first.iter().all(|(_, value)| !value.is_empty()));
        assert_eq!(first, headers(true));
    }
}
