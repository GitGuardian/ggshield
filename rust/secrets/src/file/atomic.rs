//! Atomic, locked rewrites of a dotenv file.
//!
//! The lock is a sidecar file beside the target, never the target itself: a rename replaces
//! the target's inode, so a lock on it is lost, and on Windows a handle still open on the
//! target makes the rename fail. The target is read only once the lock is held, so two
//! writers never start from the same snapshot.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Permissions for a private file we create. Existing files keep their own.
#[cfg(unix)]
const NEW_FILE_MODE: u32 = 0o600;

/// `File::lock` blocks forever; a stuck holder must surface as an error, not a hang.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// A dotenv file read while holding its sidecar lock.
pub(crate) struct LockedFile {
    _lock: File,
    path: PathBuf,
    /// `None` when there was no file yet.
    snapshot: Option<Snapshot>,
}

/// What was at the path, so the rewrite keeps its permissions and notices a concurrent edit.
struct Snapshot {
    contents: String,
    #[cfg(unix)]
    mode: u32,
    #[cfg(windows)]
    dacl: super::win_security::Dacl,
}

// The path only: the snapshot holds the user's secrets.
impl std::fmt::Debug for LockedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedFile")
            .field("path", &self.path)
            .finish()
    }
}

impl LockedFile {
    /// Lock `path` for rewriting; a directory created on the way is private.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let directory = parent_directory(path);
        create_private_dir_all(directory)
            .with_context(|| format!("creating {}", directory.display()))?;
        let lock = lock_sidecar(&lock_path(path))?;
        let snapshot = read_snapshot(path)?;
        Ok(LockedFile {
            _lock: lock,
            path: path.to_path_buf(),
            snapshot,
        })
    }

    /// Empty when the file does not exist yet.
    pub(crate) fn read(&mut self) -> Result<String> {
        Ok(self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.contents.clone())
            .unwrap_or_default())
    }

    /// Returns one message per leftover temporary collected. The sweep is here,
    /// not in `open`, so every deletion has a caller that reports it.
    pub(crate) fn replace(&self, contents: &str) -> Result<Vec<String>> {
        let collected = collect_stale_temporaries(&self.path);
        write_atomically(self, contents)?;
        Ok(collected)
    }
}

/// No handle stays open on the target: Windows cannot rename over an open file.
fn read_snapshot(path: &Path) -> Result<Option<Snapshot>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!("inspecting {}", path.display())));
        }
    }
    // Error message only; `open_for_read`'s `O_NOFOLLOW` is the real guard.
    check_regular_file(path, "write")?;
    let mut file = open_for_read(path)?;
    ensure_regular_handle(&file, path)?;
    ensure_not_hard_linked(&file, path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("reading {}", path.display()))?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        file.metadata()
            .with_context(|| format!("inspecting {}", path.display()))?
            .permissions()
            .mode()
            & 0o7777
    };
    #[cfg(windows)]
    let dacl = super::win_security::Dacl::of(&file)
        .with_context(|| format!("reading the permissions of {}", path.display()))?;
    Ok(Some(Snapshot {
        contents,
        #[cfg(unix)]
        mode,
        #[cfg(windows)]
        dacl,
    }))
}

fn parent_directory(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Named like the temporaries, so `.env*` ignore rules cover it, but never swept with them.
fn lock_path(path: &Path) -> PathBuf {
    let mut name = temporary_prefix(path);
    name.push("lock");
    parent_directory(path).join(name)
}

fn open_for_read(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return anyhow::anyhow!(
                "{} is a symbolic link; refusing to read through it",
                path.display()
            );
        }
        anyhow::Error::new(error).context(format!("reading {}", path.display()))
    })
}

/// Checked on the handle, not the path, so the answer cannot change underneath.
fn ensure_regular_handle(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(())
}

/// Private whatever the umask: the shell hook refuses a group-writable repository store.
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Read `path`, or `None` when it does not exist.
pub(crate) fn read_to_string(path: &Path) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!("reading {}", path.display())));
        }
    }
    // Checked for the error message; `open_for_read` is what makes it safe.
    check_regular_file(path, "read")?;
    let mut file = open_for_read(path)?;
    ensure_regular_handle(&file, path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(contents))
}

/// Friendly error for symlinks and non-regular files; the race is closed by
/// `O_NOFOLLOW` and [`ensure_regular_handle`], not here.
fn check_regular_file(path: &Path, verb: &str) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!("inspecting {}", path.display())));
        }
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "{} is a symbolic link; refusing to {verb} through it",
            path.display()
        );
    }
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(())
}

/// Lock a dedicated lock file. It is never renamed or deleted, so the lock always
/// lives on the inode every writer opens.
pub(crate) fn lock_sidecar(path: &Path) -> Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    check_regular_file(path, "lock")?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        // `O_NONBLOCK`: a fifo planted here would otherwise block `open(2)` forever.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        // No FILE_SHARE_DELETE: the lock file cannot be deleted out from under a holder.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening the lock file {}", path.display()))?;
    ensure_regular_handle(&file, path)?;
    lock_exclusive(&file, path)?;
    Ok(file)
}

fn lock_exclusive(file: &File, path: &Path) -> Result<()> {
    lock_exclusive_within(file, path, LOCK_TIMEOUT)
}

fn lock_exclusive_within(file: &File, path: &Path, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(
                    anyhow::Error::new(error).context(format!("locking {}", path.display()))
                );
            }
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "gave up waiting {}s for the lock on {}: another gitguardian process is holding \
                 it, or one was killed while holding it",
                timeout.as_secs(),
                path.display()
            );
        }
        std::thread::sleep(LOCK_POLL);
    }
}

/// Refuse hard-linked files: the rename would leave the old plaintext inode
/// readable through the other name.
#[cfg(unix)]
fn ensure_not_hard_linked(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let links = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?
        .nlink();
    if links > 1 {
        bail!(
            "{} has {links} hard links, so it is the same file under another name. Replacing it \
             leaves the old contents readable through the other name — plaintext values \
             included. Break the link (copy the file over itself) first",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_not_hard_linked(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Atomic write for small side files (trust store, test keystore); dotenv files
/// go through [`LockedFile`].
pub(crate) fn replace_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = parent_directory(path);
    // A leftover of the test keystore holds the master key and nothing else
    // ever sweeps this directory.
    let prefix = temporary_prefix(path);
    remove_stale_temporaries(directory, &prefix);
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .rand_bytes(RANDOM_NAME_LEN)
        .tempfile_in(directory)
        .with_context(|| format!("creating a temporary file in {}", directory.display()))?;
    apply_new_file_permissions(&temp)?;
    temp.write_all(bytes).context("writing the file")?;
    temp.flush().context("writing the file")?;
    temp.as_file().sync_all().context("flushing to disk")?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;
    sync_directory(directory)?;
    Ok(())
}

fn write_atomically(locked: &LockedFile, contents: &str) -> Result<()> {
    let path = locked.path.as_path();
    check_regular_file(path, "write")?;
    let directory = parent_directory(path);

    let prefix = temporary_prefix(path);
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .rand_bytes(RANDOM_NAME_LEN)
        .tempfile_in(directory)
        .with_context(|| format!("creating a temporary file in {}", directory.display()))?;
    match &locked.snapshot {
        Some(snapshot) => apply_snapshot_permissions(&temp, snapshot)?,
        None => apply_new_file_permissions(&temp)?,
    }
    temp.write_all(contents.as_bytes())
        .context("writing the updated file")?;
    temp.flush().context("writing the updated file")?;
    temp.as_file().sync_all().context("flushing to disk")?;

    // Only gitguardian takes the lock, so an editor's save may have landed since the
    // read; renaming over it would silently discard that edit.
    let current = read_snapshot(path)?;
    if current.as_ref().map(|current| &current.contents)
        != locked.snapshot.as_ref().map(|snapshot| &snapshot.contents)
    {
        bail!(
            "{} was changed or replaced by another program while gitguardian was rewriting it (an \
             editor saving the file, most likely), so writing now would discard that change. \
             Nothing was written; re-run the command",
            path.display()
        );
    }
    drop(current);

    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;

    // Without this the rename may not survive a crash.
    sync_directory(directory)?;
    Ok(())
}

/// A rename is only durable once its directory is synced. Windows has no std
/// equivalent (opening a directory needs FILE_FLAG_BACKUP_SEMANTICS).
#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .with_context(|| format!("flushing {}", directory.display()))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

/// Delete `path`'s leftover temporaries, as one message per deletion. Caller
/// must hold the lock on `path`.
pub(crate) fn collect_stale_temporaries(path: &Path) -> Vec<String> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    remove_stale_temporaries(directory, &temporary_prefix(path))
        .into_iter()
        .map(|removed| {
            format!(
                "removed {}, a leftover copy of this file from a write that was killed before it \
                 finished",
                removed.display()
            )
        })
        .collect()
}

/// The target's name is used verbatim (sanitising collides distinct targets and
/// the sweep would delete a live temporary) and in front, so `.env*` ignores it.
fn temporary_prefix(path: &Path) -> std::ffi::OsString {
    let name = path.file_name().unwrap_or_default();
    let mut prefix = std::ffi::OsString::with_capacity(name.len() + PREFIX_TAG.len());
    // Truncate long names and add a digest: stays under the component limit
    // without two targets sharing a prefix.
    if name.len() > MAX_PREFIX_NAME {
        let bytes = name.as_encoded_bytes();
        let mut cut = MAX_PREFIX_NAME;
        while cut > 0 && bytes[cut] & 0xc0 == 0x80 {
            cut -= 1;
        }
        // SAFETY: `cut` is a char boundary within bytes from `as_encoded_bytes`.
        prefix.push(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&bytes[..cut]) });
        prefix.push(format!("-{:016x}", digest(bytes)));
    } else {
        prefix.push(name);
    }
    prefix.push(PREFIX_TAG);
    prefix
}

const PREFIX_TAG: &str = ".gitguardian-";

/// Leaves room under a 255-byte component limit for tag, digest, random part and `.tmp`.
const MAX_PREFIX_NAME: usize = 160;

fn digest(bytes: &[u8]) -> u64 {
    // FNV-1a: stable across builds, unlike `DefaultHasher`; a changing prefix
    // would orphan the previous release's leftovers.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Delete leftovers of a killed write; caller holds the target's lock. Only the
/// exact generated name shape matches, so hand-made look-alikes survive.
fn remove_stale_temporaries(directory: &Path, prefix: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let prefix = prefix.as_encoded_bytes();
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        if is_generated_temporary(name.as_encoded_bytes(), prefix)
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed.push(entry.path());
        }
    }
    removed
}

/// Far longer than tempfile's default: it is all that separates our temporaries
/// from hand-named files like `.env.gitguardian-backupABC123.tmp`.
const RANDOM_NAME_LEN: usize = 22;

/// Whether `name` has the exact shape [`write_atomically`] generates.
fn is_generated_temporary(name: &[u8], prefix: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(random) = rest.strip_suffix(b".tmp") else {
        return false;
    };
    random.len() == RANDOM_NAME_LEN && random.iter().all(u8::is_ascii_alphanumeric)
}

/// The mode (Unix) or DACL (Windows) of the file that was read, captured from its handle.
#[cfg(unix)]
fn apply_snapshot_permissions(temp: &tempfile::NamedTempFile, snapshot: &Snapshot) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(snapshot.mode))
        .context("setting file permissions")
}

#[cfg(windows)]
fn apply_snapshot_permissions(temp: &tempfile::NamedTempFile, snapshot: &Snapshot) -> Result<()> {
    snapshot
        .dacl
        .apply_to(temp.path())
        .context("copying the file's permissions")
}

#[cfg(not(any(unix, windows)))]
fn apply_snapshot_permissions(_temp: &tempfile::NamedTempFile, _snapshot: &Snapshot) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn apply_new_file_permissions(temp: &tempfile::NamedTempFile) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(NEW_FILE_MODE))
        .context("setting file permissions")
}

#[cfg(windows)]
fn apply_new_file_permissions(temp: &tempfile::NamedTempFile) -> Result<()> {
    super::win_security::restrict_to_current_user(temp.path())
        .context("restricting the file to the current user")
}

#[cfg(not(any(unix, windows)))]
fn apply_new_file_permissions(_temp: &tempfile::NamedTempFile) -> Result<()> {
    Ok(())
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_new_file_is_created_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        LockedFile::open(&path).unwrap().replace("A=1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_files_permissions_are_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let mut locked = LockedFile::open(&path).unwrap();
        assert_eq!(locked.read().unwrap(), "A=1\n");
        locked.replace("A=2\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "mode was {:o}", mode & 0o777);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=2\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.env");
        let link = directory.path().join(".env");
        std::fs::write(&real, "A=1\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = format!("{:#}", LockedFile::open(&link).unwrap_err());
        assert!(error.contains("refusing to write through it"), "{error}");
        let error = format!("{:#}", read_to_string(&link).unwrap_err());
        assert!(error.contains("refusing to read through it"), "{error}");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "A=1\n");
    }

    /// The raw opener refuses a symlink, so winning the check/open race gains nothing.
    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_in_after_the_check_still_cannot_be_followed() {
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim.env");
        let link = directory.path().join(".env");
        std::fs::write(&victim, "STOLEN=secret\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let error = super::open_for_read(&link).unwrap_err();
        assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "STOLEN=secret\n",
            "the victim file must be untouched"
        );
    }

    /// Permissions come from the file that was read, not from a 0666 look-alike put in its place.
    #[cfg(unix)]
    #[test]
    fn permissions_come_from_the_file_that_was_read_not_the_pathname() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let locked = LockedFile::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "A=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        locked.replace("A=2\n").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the mode came from the pathname: {mode:o}");
    }

    #[cfg(windows)]
    #[test]
    fn a_new_private_file_gets_a_dacl_of_its_own() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        LockedFile::open(&path).unwrap().replace("A=1\n").unwrap();
        let dacl = super::super::win_security::Dacl::of(&File::open(&path).unwrap()).unwrap();
        assert!(
            dacl.is_protected(),
            "the new file inherited its directory's ACL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_rewrite_keeps_the_files_restrictive_dacl() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();
        super::super::win_security::restrict_to_current_user(&path).unwrap();

        LockedFile::open(&path).unwrap().replace("A=2\n").unwrap();

        let dacl = super::super::win_security::Dacl::of(&File::open(&path).unwrap()).unwrap();
        assert!(
            dacl.is_protected(),
            "the rewrite fell back to the directory's ACL"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=2\n");
    }

    /// An editor's rename over the path after locking makes the write refuse, not clobber.
    #[test]
    fn a_target_replaced_after_the_lock_is_not_overwritten_with_the_stale_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();

        let mut locked = LockedFile::open(&path).unwrap();
        assert_eq!(locked.read().unwrap(), "A=1\n");

        // An editor writes a new file and renames it into place.
        let editor_save = directory.path().join("editor.tmp");
        std::fs::write(&editor_save, "A=1\nEDITED=by-the-user\n").unwrap();
        std::fs::rename(&editor_save, &path).unwrap();

        let error = locked.replace("A=2\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("replaced by another program"), "{message}");
        assert!(message.contains("Nothing was written"), "{message}");
        // The user's save survives, and no temporary is left behind.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "A=1\nEDITED=by-the-user\n"
        );
        assert_eq!(names_in(directory.path()), [".env", LOCK_NAME]);
    }

    /// Hard-linked files are refused for writing but still readable.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_file_is_refused_for_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        let shared = directory.path().join("shared.env");
        std::fs::write(&path, "API_KEY=cleartext\n").unwrap();
        std::fs::hard_link(&path, &shared).unwrap();

        let error = LockedFile::open(&path).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("hard link"), "{message}");
        assert!(
            message.contains("readable through the other name"),
            "{message}"
        );

        assert_eq!(
            read_to_string(&path).unwrap().as_deref(),
            Some("API_KEY=cleartext\n")
        );
        std::fs::remove_file(&shared).unwrap();
        LockedFile::open(&path)
            .unwrap()
            .replace("API_KEY=x\n")
            .unwrap();
    }

    /// A never-released lock times out with a message naming the path.
    #[test]
    fn waiting_for_a_lock_gives_up_and_says_what_it_was_waiting_on() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.lock");
        let held = lock_sidecar(&path).unwrap();

        // A second open file description is a different `flock` holder.
        let second = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let timeout = std::time::Duration::from_millis(200);
        let start = std::time::Instant::now();
        let error = lock_exclusive_within(&second, &path, timeout).unwrap_err();
        let waited = start.elapsed();

        let message = format!("{error:#}");
        assert!(message.contains("gave up waiting"), "{message}");
        assert!(message.contains("keyset.lock"), "{message}");
        assert!(waited >= timeout, "it did not actually wait: {waited:?}");
        drop(held);
    }

    #[test]
    fn a_directory_is_not_a_dotenv_file() {
        let directory = tempfile::tempdir().unwrap();
        let error = read_to_string(directory.path()).unwrap_err();
        assert!(format!("{error:#}").contains("not a regular file"));
    }

    #[test]
    fn reading_a_missing_file_is_not_an_error() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            read_to_string(&directory.path().join("nope.env"))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_original_file_intact() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores directory permissions, so the write would just succeed.
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();

        let locked = LockedFile::open(&path).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let error = locked.replace("A=2\n").unwrap_err();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(format!("{error:#}").contains("temporary file"), "{error:#}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
    }

    const LOCK_NAME: &str = ".env.gitguardian-lock";

    fn names_in(directory: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    /// Only the lock file stays beside the target, and it is not a temporary to sweep.
    #[test]
    fn no_temporary_file_is_left_behind() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        LockedFile::open(&path).unwrap().replace("A=1\n").unwrap();
        LockedFile::open(&path).unwrap().replace("A=2\n").unwrap();
        assert_eq!(names_in(directory.path()), [".env", LOCK_NAME]);
    }

    /// A writer waiting on the lock reads what the holder wrote, never the file it replaced.
    #[test]
    fn a_waiting_writer_starts_from_the_holders_result() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "BASE=0\n").unwrap();

        let first = LockedFile::open(&path).unwrap();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let mut second = LockedFile::open(&path).unwrap();
                let contents = second.read().unwrap();
                second.replace(&format!("{contents}BBB=b\n")).unwrap();
            });
            std::thread::sleep(std::time::Duration::from_millis(100));
            first.replace("BASE=0\nAAA=a\n").unwrap();
            drop(first);
            waiter.join().unwrap();
        });
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "BASE=0\nAAA=a\nBBB=b\n"
        );
    }

    /// Two concurrent read-modify-writes of different keys both survive.
    #[test]
    fn concurrent_read_modify_writes_do_not_lose_a_key() {
        for attempt in 0..8 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(".env");
            std::fs::write(&path, "BASE=0\n").unwrap();

            std::thread::scope(|scope| {
                for key in ["AAA", "BBB"] {
                    let path = path.clone();
                    scope.spawn(move || {
                        let mut locked = LockedFile::open(&path).unwrap();
                        let contents = locked.read().unwrap();
                        // Widen the race window.
                        std::thread::yield_now();
                        locked.replace(&format!("{contents}{key}={key}\n")).unwrap();
                    });
                }
            });

            let contents = std::fs::read_to_string(&path).unwrap();
            assert!(
                contents.contains("AAA=AAA") && contents.contains("BBB=BBB"),
                "attempt {attempt} lost a key: {contents:?}"
            );
            assert!(
                contents.contains("BASE=0"),
                "attempt {attempt}: {contents:?}"
            );
        }
    }

    /// Leftovers are collected; other targets' and hand-named look-alikes survive.
    #[test]
    fn a_leftover_temporary_from_a_killed_write_is_collected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();

        let random: String = std::iter::repeat_n('a', RANDOM_NAME_LEN).collect();
        let mut leftover_name = temporary_prefix(&path);
        leftover_name.push(format!("{random}.tmp"));
        let leftover = directory.path().join(leftover_name);
        std::fs::write(&leftover, "A=1\nSECRET=plaintext\n").unwrap();
        let other = directory.path().join("other.env.gitguardian-xyz.tmp");
        std::fs::write(&other, "").unwrap();
        let mut survivors = Vec::new();
        for hand_written in ["backup", "backupABC123"] {
            let mut theirs = temporary_prefix(&path);
            theirs.push(format!("{hand_written}.tmp"));
            let theirs = directory.path().join(theirs);
            std::fs::write(&theirs, "A=1\n").unwrap();
            survivors.push(theirs);
        }

        let reported = LockedFile::open(&path).unwrap().replace("A=2\n").unwrap();

        assert!(!leftover.exists(), "the stale temporary was not collected");
        assert!(other.exists(), "another file's temporary was collected");
        for theirs in &survivors {
            assert!(
                theirs.exists(),
                "a file the user made was collected: {theirs:?}"
            );
        }
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert!(
            reported[0].contains(&format!("{random}.tmp")),
            "the deletion was not reported: {reported:?}"
        );
    }

    /// A hand-written alphanumeric name is not mistaken for a generated one.
    #[test]
    fn only_the_exact_generated_shape_is_ours_to_delete() {
        let prefix = b".env.gitguardian-";
        let ours: String = std::iter::repeat_n('q', RANDOM_NAME_LEN).collect();
        assert!(is_generated_temporary(
            format!(".env.gitguardian-{ours}.tmp").as_bytes(),
            prefix
        ));
        for theirs in [
            "backup",
            "backupABC123",
            "2026-09-01-backup",
            "beforeRotation",
            "",
        ] {
            assert!(
                !is_generated_temporary(
                    format!(".env.gitguardian-{theirs}.tmp").as_bytes(),
                    prefix
                ),
                "{theirs:?} was treated as one of ours"
            );
        }
        assert!(!is_generated_temporary(
            format!("other.gitguardian-{ours}.tmp").as_bytes(),
            prefix
        ));
        assert!(!is_generated_temporary(
            format!(".env.gitguardian-{ours}.bak").as_bytes(),
            prefix
        ));
    }

    /// Distinct names never share a prefix, even past the truncation point.
    #[test]
    fn two_files_whose_names_differ_only_in_punctuation_get_distinct_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        assert_ne!(
            temporary_prefix(&directory.path().join("a+b.env")),
            temporary_prefix(&directory.path().join("ab.env"))
        );
        let long = "x".repeat(MAX_PREFIX_NAME + 40);
        assert_ne!(
            temporary_prefix(&directory.path().join(format!("{long}-one.env"))),
            temporary_prefix(&directory.path().join(format!("{long}-two.env")))
        );
    }

    /// Leftovers start with the target's name so `.env*` gitignore rules catch them.
    #[test]
    fn a_temporary_is_named_after_the_file_it_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let prefix = temporary_prefix(&directory.path().join(".env"));
        assert_eq!(prefix, std::ffi::OsString::from(".env.gitguardian-"));
    }

    /// A second sidecar lock stays blocked while the first is held.
    #[test]
    fn a_sidecar_lock_is_exclusive_while_it_is_held() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.lock");
        let held = lock_sidecar(&path).unwrap();

        let taken = Arc::new(AtomicBool::new(false));
        let at_the_lock = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let flag = taken.clone();
            let barrier = at_the_lock.clone();
            let path = path.clone();
            let handle = scope.spawn(move || {
                barrier.wait();
                let _second = lock_sidecar(&path).unwrap();
                flag.store(true, Ordering::SeqCst);
            });

            at_the_lock.wait();
            for _ in 0..40 {
                std::thread::sleep(std::time::Duration::from_millis(5));
                assert!(
                    !taken.load(Ordering::SeqCst),
                    "the second lock was granted while the first was held"
                );
            }

            drop(held);
            handle.join().unwrap();
        });
        assert!(
            taken.load(Ordering::SeqCst),
            "the second lock was never granted after the first was released"
        );
    }

    /// A fifo at the lock path is refused rather than blocking `open(2)` forever.
    #[cfg(unix)]
    #[test]
    fn a_sidecar_lock_refuses_anything_that_is_not_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.lock");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated string.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // Bounds the damage if this regresses into blocking.
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(lock_sidecar(&path).map(drop).map_err(|e| format!("{e:#}")));
        });
        let outcome = wait
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("lock_sidecar blocked on a fifo instead of refusing it");
        let error = outcome.expect_err("a fifo was accepted as a lock file");
        assert!(error.contains("not a regular file"), "{error}");
    }

    /// `replace_bytes` sweeps leftovers, which for the test keystore hold the master key.
    #[cfg(feature = "test-keystore")]
    #[test]
    fn replace_bytes_collects_a_leftover_from_a_killed_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.json");
        std::fs::write(&path, b"{}").unwrap();

        let mut leftover_name = temporary_prefix(&path);
        leftover_name.push(format!("{}.tmp", "z".repeat(RANDOM_NAME_LEN)));
        let leftover = directory.path().join(leftover_name);
        std::fs::write(&leftover, b"{\"keys\":{\"0000\":\"fake-master-key\"}}").unwrap();

        replace_bytes(&path, b"{\"replaced\":true}").unwrap();

        assert!(
            !leftover.exists(),
            "a temporary holding the master key was left behind"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"replaced\":true}");
    }
}
