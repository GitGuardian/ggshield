//! Safe mutation of a dotenv file.
//!
//! A `.env` is a file the user owns and edits by hand, so a write must be
//! all-or-nothing: a crash, a full disk or a concurrent `gitguardian set` must
//! never leave a half-written file behind. Every write goes to a temporary
//! file in the same directory and is renamed into place, with the file and its
//! directory fsynced so the rename survives a power loss.
//!
//! # Why the lock is verified after it is taken
//!
//! The lock is an advisory `flock`, which lives on the *inode*, not on the
//! pathname — and a write here replaces the inode, because that is what
//! `rename` does. So a second writer that blocked on the lock wakes up holding
//! an exclusive lock on an inode that has already been unlinked, and every byte
//! it read came from before the first writer's rename. It would then rename its
//! own stale snapshot over the winner's file and silently discard a key.
//!
//! [`LockedFile::open`] therefore treats "I hold the lock" as a claim to be
//! checked rather than a fact: after acquiring it, it compares the locked
//! handle's `st_dev`/`st_ino` against the pathname's, and starts over when they
//! differ. Only a handle that is still the file at `path` is handed back, so the
//! read-modify-write always begins from the current contents.
//!
//! # Why it is checked a second time, before the rename
//!
//! The lock keeps *other gitguardian processes* out for the whole cycle, but
//! nothing else takes it. An editor saving `.env` renames its own freshly
//! written inode over the pathname, and that can land after we read and before
//! we `persist` — at which point the rename below would put our stale snapshot
//! back and silently discard the user's edit. So [`write_atomically`] repeats
//! the identity check just before the rename and refuses when the answer has
//! changed. It narrows the window rather than closing it — `rename(2)` has no
//! compare-and-swap — but it turns "your editor's save disappeared" into an
//! error that says so.

// A note on what is *not* protected: a `SIGKILL` or a power loss between
// creating the temporary and renaming it leaves a full copy of the replacement
// document beside the target. No writer that achieves atomicity by rename can
// avoid that; what this module does about it is give the temporary the target's
// own permissions, name it so the target's gitignore rule (`.env*`) catches it,
// and collect it — reporting every deletion — the next time the file is written.
// See [`remove_stale_temporaries`].

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Permissions for a file we create. Existing files keep their own.
#[cfg(unix)]
const NEW_FILE_MODE: u32 = 0o600;

/// How many times to re-take the lock when the file was replaced underneath it.
///
/// Each retry costs one competing writer that actually completed, so this is a
/// bound on pathological contention, not on ordinary use.
const MAX_LOCK_ATTEMPTS: usize = 40;

/// How long to wait for a lock somebody else holds before giving up.
///
/// `File::lock` blocks forever. A `set` stopped under a debugger, a process
/// killed while holding the lock on an NFS-mounted project, or a lock file an
/// attacker planted then leaves alone, would otherwise leave the next `set`
/// sitting at its `KEY: ` prompt with no output and nothing to tell the user
/// what it is waiting on. Ten seconds is far longer than any honest write of a
/// dotenv file takes and short enough to look like a hang rather than one.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How often to retry while waiting out [`LOCK_TIMEOUT`].
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Identity of an inode, as compared to decide whether the file at a path is
/// still the file we locked.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl FileId {
    fn of(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileId {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// A dotenv file opened for a read-modify-write cycle, holding an advisory
/// exclusive lock for as long as it is alive.
pub(crate) struct LockedFile {
    file: File,
    path: std::path::PathBuf,
}

// The path only: the handle's contents are the user's secrets.
impl std::fmt::Debug for LockedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedFile")
            .field("path", &self.path)
            .finish()
    }
}

impl LockedFile {
    /// Open `path` for update, creating it (mode 0600) if it does not exist,
    /// and take an advisory exclusive lock on the file that is really there.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        for _ in 0..MAX_LOCK_ATTEMPTS {
            // Checked for the error message; `open_for_update` is what actually
            // makes following a link impossible.
            check_regular_file(path, "write")?;
            let file = open_for_update(path)?;
            ensure_regular_handle(&file, path)?;
            ensure_not_hard_linked(&file, path)?;
            // Advisory: it keeps two gitguardian processes from interleaving a
            // read-modify-write, which is what we can actually control.
            lock_exclusive(&file, path)?;

            if locked_the_file_at_the_path(&file, path)? {
                return Ok(LockedFile {
                    file,
                    path: path.to_path_buf(),
                });
            }
            // Another writer renamed its own file over ours while we waited, so
            // this handle is an orphan and its contents are stale. Drop the
            // lock and start again from whatever is at `path` now.
            drop(file);
        }
        bail!(
            "gave up locking {} after {MAX_LOCK_ATTEMPTS} attempts: it is being rewritten \
             continuously by other processes",
            path.display()
        )
    }

    /// The file's current contents.
    pub(crate) fn read(&mut self) -> Result<String> {
        let mut contents = String::new();
        self.file.rewind().ok();
        self.file
            .read_to_string(&mut contents)
            .with_context(|| format!("reading {}", self.path.display()))?;
        Ok(contents)
    }

    /// Replace the file's contents atomically, keeping its permissions.
    ///
    /// Returns a message per leftover temporary file it collected on the way, so
    /// the caller can tell the user a copy of their secrets had been sitting
    /// there. Empty in the ordinary case.
    ///
    /// The sweep is here, and not in [`LockedFile::open`], so that no deletion
    /// can happen on a path that has no way to report it: a caller that takes
    /// the lock and then returns an error — a stray quote it refuses to write
    /// next to — would otherwise remove a copy of the user's secrets and say
    /// nothing about it.
    pub(crate) fn replace(&self, contents: &str) -> Result<Vec<String>> {
        let collected = collect_stale_temporaries(&self.path);
        write_atomically(&self.path, &self.file, contents)?;
        Ok(collected)
    }
}

/// Whether the locked `file` is still the inode that `path` names.
///
/// See the module docs: a lock on an inode that has been renamed away proves
/// nothing, so this is what makes the lock meaningful.
#[cfg(unix)]
fn locked_the_file_at_the_path(file: &File, path: &Path) -> Result<bool> {
    let locked = file
        .metadata()
        .with_context(|| format!("inspecting the locked {}", path.display()))?;
    match std::fs::symlink_metadata(path) {
        Ok(current) => Ok(FileId::of(&current) == FileId::of(&locked)),
        // Unlinked while we waited: whatever we hold is not the file any more.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(anyhow::Error::new(error).context(format!("inspecting {}", path.display())))
        }
    }
}

/// Windows has neither `st_dev`/`st_ino` nor these rename semantics; the
/// advisory lock is all there is.
#[cfg(not(unix))]
fn locked_the_file_at_the_path(_file: &File, _path: &Path) -> Result<bool> {
    Ok(true)
}

/// Open `path` read/write, creating it private, and never following a symlink.
///
/// `O_NOFOLLOW` rather than a `symlink_metadata` check alone: the check and the
/// open are two syscalls, and between them the path can be swapped for a link
/// to somebody else's dotenv file — which we would then read secrets out of, or
/// write the mode of.
fn open_for_update(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(NEW_FILE_MODE);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return anyhow::anyhow!(
                "{} is a symbolic link; refusing to write through it",
                path.display()
            );
        }
        anyhow::Error::new(error).context(format!("opening {}", path.display()))
    })
}

/// Open `path` read-only, never following a symlink.
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

/// Fail unless the *opened handle* is a plain file.
///
/// Checked on the handle, not the path: this is the inode we will actually read
/// and rename over, so nothing can change underneath the answer.
fn ensure_regular_handle(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(())
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

/// Fail on anything that is not a plain file we own the bytes of.
///
/// Following a symlink would reach through it — possibly outside the project,
/// possibly onto something that is not a dotenv file at all — and a fifo or a
/// device cannot be replaced by a rename.
///
/// `verb` is what the caller was about to do, so the message describes the
/// operation the user actually asked for rather than always claiming a write.
///
/// This is for the error message. The race between this check and the open is
/// closed by `O_NOFOLLOW` plus [`ensure_regular_handle`], not by this function.
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

/// Take an exclusive advisory lock on a dedicated lock file.
///
/// For serialising something that is not itself a dotenv file — the keyring
/// blob, which has no path to lock. The lock file is only ever created and
/// locked, never renamed, so it needs none of [`LockedFile`]'s inode dance.
pub(crate) fn lock_sidecar(path: &Path) -> Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Checked for the error message, like the dotenv path: a symlink or a fifo
    // already sitting there is named rather than silently opened.
    check_regular_file(path, "lock")?;
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        // The lock file may live in a shared directory; never follow a link
        // planted there.
        //
        // `O_NONBLOCK` is what closes the check/open race for a *fifo*: opening
        // one for writing blocks until a reader arrives, so without it a fifo
        // planted at this path between the check and the open wedges the process
        // inside `open(2)` — before any of our own timeouts can apply, and with
        // no output at all. Non-blocking, the open fails or returns a handle
        // `ensure_regular_handle` then rejects. It has no effect on a regular
        // file, and `flock` is not an `O_NONBLOCK` operation.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening the lock file {}", path.display()))?;
    // On the handle, so nothing can change underneath the answer.
    ensure_regular_handle(&file, path)?;
    lock_exclusive(&file, path)?;
    Ok(file)
}

/// Take the exclusive advisory lock on `file`, giving up after
/// [`LOCK_TIMEOUT`] with a message that names the path.
fn lock_exclusive(file: &File, path: &Path) -> Result<()> {
    lock_exclusive_within(file, path, LOCK_TIMEOUT)
}

/// [`lock_exclusive`] with the deadline spelled out, so a test can watch it
/// expire without waiting out the shipped one.
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

/// Fail when the file we are about to replace has another name.
///
/// A write here is a rename over the path, which leaves the *old* inode intact
/// and reachable through every other link to it. So `.env` and `shared.env`
/// hard-linked together, sealed by `encrypt`, would leave `shared.env` holding
/// the cleartext — committable, readable, and reported as encrypted. There is
/// nothing to do about it while keeping the write atomic, so it is refused.
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

/// Replace `path`'s bytes atomically, creating it private.
///
/// For a file with no [`LockedFile`] around it: a reader that is not holding the
/// lock must still never see a half-written file, and `std::fs::write`
/// truncates before it writes, so a concurrent reader can observe an empty or
/// partial one.
///
/// For the small side files, not for dotenv files: every dotenv write goes
/// through [`LockedFile`], which additionally locks and re-verifies the inode.
/// Callers are the trust store and, under `test-keystore`, the file-backed
/// stand-in for the OS credential store.
pub(crate) fn replace_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // Sweep first, exactly as `write_atomically` does. This writer's target is
    // the keyring stand-in, so an interrupted earlier run leaves a temporary
    // holding the base64 *master key*; nothing else ever looks at this
    // directory, so if this write does not collect it, nothing will.
    let prefix = temporary_prefix(path);
    remove_stale_temporaries(directory, &prefix);
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .rand_bytes(RANDOM_NAME_LEN)
        .tempfile_in(directory)
        .with_context(|| format!("creating a temporary file in {}", directory.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(NEW_FILE_MODE))
            .context("setting file permissions")?;
    }
    temp.write_all(bytes).context("writing the file")?;
    temp.flush().context("writing the file")?;
    temp.as_file().sync_all().context("flushing to disk")?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;
    sync_directory(directory)?;
    Ok(())
}

/// Write `contents` to `path` via a same-directory temporary file and a
/// rename, so readers see either the old file or the new one.
///
/// `locked` is the handle [`LockedFile`] verified and holds the lock on: its
/// permissions come from that inode by `fstat`, never from the pathname.
fn write_atomically(path: &Path, locked: &File, contents: &str) -> Result<()> {
    check_regular_file(path, "write")?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };

    // Named after the file it replaces, so a leftover can be attributed — see
    // `remove_stale_temporaries`.
    let prefix = temporary_prefix(path);
    let mut temp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .rand_bytes(RANDOM_NAME_LEN)
        .tempfile_in(directory)
        .with_context(|| format!("creating a temporary file in {}", directory.display()))?;
    set_permissions(&temp, locked)?;
    temp.write_all(contents.as_bytes())
        .context("writing the updated file")?;
    temp.flush().context("writing the updated file")?;
    temp.as_file().sync_all().context("flushing to disk")?;

    // The last thing before the commit point: is the pathname still the inode we
    // locked and read? Only gitguardian processes take the lock, so anything
    // else that writes this file — an editor's atomic save above all — can have
    // replaced it since. See the module docs: renaming over that would put our
    // stale snapshot back and lose the user's edit without a word. `temp` is
    // dropped unpersisted, which deletes it.
    if !locked_the_file_at_the_path(locked, path)? {
        bail!(
            "{} was replaced by another program while gitguardian was rewriting it (an editor \
             saving the file, most likely), so writing now would discard that change. Nothing \
             was written; re-run the command",
            path.display()
        );
    }

    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;

    // fsync the directory too: without it the rename itself may not survive a
    // crash, even though the file's own contents did.
    sync_directory(directory)?;
    Ok(())
}

/// Make the directory entry the rename just created durable.
///
/// POSIX only. A rename is not on disk until its parent directory is synced,
/// which is why this exists at all; Windows exposes no equivalent through std
/// (opening a directory there needs FILE_FLAG_BACKUP_SEMANTICS, so
/// `File::open` on one fails with "Access is denied"), and the rename records
/// the entry itself.
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

/// Delete `path`'s leftover temporaries, as one message per deletion.
///
/// Only ever called with the exclusive lock on `path` held; see
/// [`remove_stale_temporaries`] for why that is what makes it safe.
///
/// `pub(crate)` as well as being called from [`LockedFile::replace`]: a delete
/// that removes nothing writes nothing, and skipping the sweep there would
/// leave a killed writer's copy of the file uncollected until the next write
/// that happens to succeed.
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

/// Temporary-file prefix for writes to `path`, e.g. `.env.gitguardian-`.
///
/// Encoding the target's name is what makes a leftover collectable: the caller
/// holds the exclusive lock on `path`, so no other live writer of *this* file
/// exists, while a concurrent writer of a different file in the same directory
/// gets a different prefix and is left alone.
///
/// Two properties that the obvious spelling of this gets wrong:
///
/// - The target's name is used **verbatim**, not sanitised. Sanitising maps
///   distinct targets onto one prefix — `a+b.env` and `ab.env` both reduce to
///   `ab.env` — and the sweep below then deletes another writer's *live*
///   temporary, so its `persist` fails. The name came from a real directory
///   entry, so it needs no cleaning to be a legal filename.
/// - The name goes in **front**. A leftover is a full copy of the file, so a
///   `.env` that is gitignored must not spawn a sibling that is not:
///   `.env.gitguardian-x.tmp` is caught by the `.env*` rule people already
///   have, where `.gitguardian-.env-x.tmp` slips past it and gets committed.
fn temporary_prefix(path: &Path) -> std::ffi::OsString {
    let name = path.file_name().unwrap_or_default();
    let mut prefix = std::ffi::OsString::with_capacity(name.len() + PREFIX_TAG.len());
    // A long name plus the tag plus tempfile's random part can exceed the
    // filesystem's per-component limit. Truncating alone would put two targets
    // back on one prefix, so what is dropped is replaced by a digest of the
    // whole name.
    if name.len() > MAX_PREFIX_NAME {
        let bytes = name.as_encoded_bytes();
        // On a char boundary in the OsStr's own encoding, so the result is
        // still a well-formed `OsString`.
        let mut cut = MAX_PREFIX_NAME;
        while cut > 0 && bytes[cut] & 0xc0 == 0x80 {
            cut -= 1;
        }
        // SAFETY: `bytes` came from `as_encoded_bytes` and `cut` is on a
        // boundary between encoded characters, which is what the safety
        // contract asks for.
        prefix.push(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(&bytes[..cut]) });
        prefix.push(format!("-{:016x}", digest(bytes)));
    } else {
        prefix.push(name);
    }
    prefix.push(PREFIX_TAG);
    prefix
}

/// What every temporary this writes has between the target's name and
/// tempfile's random part.
const PREFIX_TAG: &str = ".gitguardian-";

/// Longest target name carried into a prefix verbatim. Leaves room under a
/// 255-byte component limit for the tag, the digest, tempfile's random part
/// and `.tmp`.
const MAX_PREFIX_NAME: usize = 160;

/// A short, stable digest of `bytes`, to keep truncated prefixes distinct.
fn digest(bytes: &[u8]) -> u64 {
    // FNV-1a: a couple of lines, no dependency, and stable across builds —
    // which `DefaultHasher` is not, and a prefix that changes between releases
    // would orphan the leftovers of the previous one.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Delete temporary files left by an earlier interrupted write of this file,
/// returning what was removed.
///
/// A `SIGKILL` or a power loss between "create the temporary" and "rename it"
/// leaves a `<name>.gitguardian-<random>.tmp` sibling behind, holding a full
/// copy of the file — plaintext values included, under `--plain`. Best-effort: a
/// file we cannot remove is not a reason to fail the write the user asked for.
///
/// Only ever called with the exclusive lock on the target held, which is what
/// makes deleting by prefix safe: no other live writer of *this* file exists,
/// and [`temporary_prefix`] guarantees no other target shares the prefix.
///
/// Matching the whole *generated* name and not just the prefix is what keeps a
/// file the user made from being deleted. `.env.gitguardian-backup.tmp`, or
/// `.env.gitguardian-backupABC123.tmp`, is a perfectly plausible thing for
/// somebody to have created by hand, and it may hold the only copy of a value;
/// only the shape this writer itself produces — prefix, exactly
/// [`RANDOM_NAME_LEN`] alphanumeric characters, `.tmp` — is ours to remove. It is
/// still a shape and not a proof, so the caller reports every deletion rather
/// than doing it silently.
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

/// How many random characters go between the prefix and the `.tmp` suffix.
///
/// Set explicitly, and much longer than `tempfile`'s default of six, because
/// this is the only thing that distinguishes a temporary of ours from a file
/// somebody created by hand. Twelve was not enough: the alphabet is
/// `[A-Za-z0-9]`, and `.env.gitguardian-backupABC123.tmp` — a backup somebody
/// tagged with a ticket or a date — is twelve of those characters and was
/// therefore deleted by the next write. Twenty-two is a length no hand-written
/// name lands on, and it is still only a *shape*, which is why every deletion is
/// reported rather than done silently.
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

/// Give the replacement the permissions of the file it replaces, or 0600 when
/// there is no file to replace.
///
/// Read from the locked handle with `fstat`, never from the pathname:
/// `std::fs::metadata` follows symlinks, so a path-based lookup would copy the
/// mode of whatever a link pointed at — possibly a world-readable file — onto
/// the dotenv file we are about to write.
#[cfg(unix)]
fn set_permissions(temp: &tempfile::NamedTempFile, locked: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = locked
        .metadata()
        .map(|metadata| metadata.permissions().mode() & 0o7777)
        .unwrap_or(NEW_FILE_MODE);
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .context("setting file permissions")
}

#[cfg(not(unix))]
fn set_permissions(temp: &tempfile::NamedTempFile, locked: &File) -> Result<()> {
    if let Ok(metadata) = locked.metadata() {
        temp.as_file()
            .set_permissions(metadata.permissions())
            .context("setting file permissions")?;
    }
    Ok(())
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
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

        // The message names the operation the caller actually asked for: a
        // failed `get` that says "refusing to write" sends the reader hunting
        // for a write that never happened.
        let error = format!("{:#}", LockedFile::open(&link).unwrap_err());
        assert!(error.contains("refusing to write through it"), "{error}");
        let error = format!("{:#}", read_to_string(&link).unwrap_err());
        assert!(error.contains("refusing to read through it"), "{error}");
        // The link target is untouched.
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "A=1\n");
    }

    /// Finding 4: the pathname check and the open are separate syscalls, so the
    /// check cannot be what protects us. Simulated by handing the opener a path
    /// that is already a symlink — with `O_NOFOLLOW` the open itself fails, so
    /// winning the race buys the attacker nothing.
    #[cfg(unix)]
    #[test]
    fn a_symlink_swapped_in_after_the_check_still_cannot_be_followed() {
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim.env");
        let link = directory.path().join(".env");
        std::fs::write(&victim, "STOLEN=secret\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        // Both raw openers refuse the link, which is the state the check would
        // have missed had it been swapped in after `check_regular_file` ran.
        let error = super::open_for_update(&link).unwrap_err();
        assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
        let error = super::open_for_read(&link).unwrap_err();
        assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "STOLEN=secret\n",
            "the victim file must be untouched"
        );
    }

    /// Finding 4, Google's variant: permissions must come from the inode we
    /// locked, by `fstat`, not from a pathname lookup.
    ///
    /// Finding 24: the decoy has to be **at `path`**. Put anywhere else it
    /// proves nothing — `path` still names the original 0600 file, so reading
    /// the mode from the pathname would give the right answer by accident.
    ///
    /// Round-3 finding 11: the whole `replace` can no longer be used to show
    /// this, because swapping the pathname for another inode is now *refused*
    /// (see below). So the property is pinned on the one function that decides
    /// it: the pathname holds a 0666 decoy, and `set_permissions` still has to
    /// produce 0600 from the locked handle alone.
    #[cfg(unix)]
    #[test]
    fn permissions_come_from_the_locked_handle_not_the_pathname() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let locked = LockedFile::open(&path).unwrap();

        // The pathname now names a different, world-readable file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "DECOY=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let temp = tempfile::Builder::new()
            .tempfile_in(directory.path())
            .unwrap();
        set_permissions(&temp, &locked.file).unwrap();
        let mode = temp.as_file().metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the mode came from the pathname, not the locked inode: {mode:o}"
        );
    }

    /// Round-3 finding 11: the identity check after `flock` proves the read
    /// started from the current file; it says nothing about the moment of the
    /// rename. Only gitguardian processes take the lock, so an editor's atomic
    /// save can land in between — and renaming our snapshot over it would
    /// discard that save silently.
    ///
    /// Simulated exactly as the editor does it: a fresh inode is renamed over
    /// the pathname after the lock was taken and verified. The write must refuse
    /// and leave the newer file alone.
    #[cfg(unix)]
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
        let names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![".env".to_string()], "{names:?}");
    }

    /// Finding 14: a hard-linked dotenv cannot be replaced safely.
    ///
    /// The rename leaves the old inode in place, reachable through every other
    /// name it has — so `encrypt` would report success while the cleartext sat
    /// in the other file, committable and readable. Reading one is still fine;
    /// only the write is refused.
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

        // Reading is unaffected: it copies nothing and leaves no stale inode.
        assert_eq!(
            read_to_string(&path).unwrap().as_deref(),
            Some("API_KEY=cleartext\n")
        );
        // Breaking the link makes it writable again, which is what the message
        // tells the user to do.
        std::fs::remove_file(&shared).unwrap();
        LockedFile::open(&path)
            .unwrap()
            .replace("API_KEY=x\n")
            .unwrap();
    }

    /// Finding 20: a lock nobody will ever release must not hang the CLI
    /// silently. The message names the path so the user can see what is holding
    /// it.
    #[test]
    fn waiting_for_a_lock_gives_up_and_says_what_it_was_waiting_on() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.lock");
        let held = lock_sidecar(&path).unwrap();

        // Same path, a second open file description: `flock` treats it as a
        // different holder, exactly as another process would be.
        let second = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        // A short deadline rather than the shipped ten seconds: what is under
        // test is that it gives up at all and says what it was waiting on.
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

        // The whole test hinges on a directory we cannot write to, and root
        // ignores directory permissions — under root the write would simply
        // succeed and the assertions would be meaningless. CI runs as root in a
        // container, so skip rather than fail on something that is not a defect.
        // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();

        let locked = LockedFile::open(&path).unwrap();
        // No temporary file can be created in a directory we cannot write.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let error = locked.replace("A=2\n").unwrap_err();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(format!("{error:#}").contains("temporary file"), "{error:#}");
        // The rename never happened, so the old contents are still there.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        LockedFile::open(&path).unwrap().replace("A=1\n").unwrap();
        let names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![".env".to_string()]);
    }

    /// Finding 1: the lock must be verified against the path after it is taken.
    ///
    /// Simulates the losing writer directly: it opens and locks the file, then
    /// another writer's `replace` renames a new inode over the path. The handle
    /// is now an orphan, and that is exactly what the check has to notice.
    #[cfg(unix)]
    #[test]
    fn a_lock_on_a_renamed_away_inode_is_not_the_file_any_more() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "BASE=0\n").unwrap();

        let orphaned = super::open_for_update(&path).unwrap();
        assert!(
            locked_the_file_at_the_path(&orphaned, &path).unwrap(),
            "it is the file at the path to begin with"
        );

        // A competing writer completes a full atomic replace.
        LockedFile::open(&path)
            .unwrap()
            .replace("BASE=0\nAAA=a\n")
            .unwrap();

        assert!(
            !locked_the_file_at_the_path(&orphaned, &path).unwrap(),
            "the handle is an unlinked orphan and must not be trusted"
        );
    }

    /// Finding 1, end to end: two threads doing a read-modify-write of
    /// different keys must both survive. Before the fix the loser's key was
    /// silently dropped in essentially every run.
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
                        // Widen the window the bug lived in.
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

    /// Finding 17a: a temporary left by a killed write is collected by the next
    /// write of the same file, instead of sitting in the project directory
    /// holding a copy of its contents.
    #[test]
    fn a_leftover_temporary_from_a_killed_write_is_collected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, "A=1\n").unwrap();

        // The shape this writer generates: the target's name, the tag, exactly
        // RANDOM_NAME_LEN alphanumerics, `.tmp`. Built from the constant so the
        // test cannot drift from the writer.
        let random: String = std::iter::repeat_n('a', RANDOM_NAME_LEN).collect();
        let mut leftover_name = temporary_prefix(&path);
        leftover_name.push(format!("{random}.tmp"));
        let leftover = directory.path().join(leftover_name);
        std::fs::write(&leftover, "A=1\nSECRET=plaintext\n").unwrap();
        // A temporary belonging to another file must survive.
        let other = directory.path().join("other.env.gitguardian-xyz.tmp");
        std::fs::write(&other, "").unwrap();
        // Finding 8: and so must a file of the user's own that happens to share
        // the prefix and the suffix. It may hold the only copy of a value.
        //
        // Round-3 finding 12b: the old decoy here was `backup.tmp`, which is
        // deliberately too short to match the predicate — so the test could not
        // fail however loose the predicate became. These two are the shapes that
        // actually distinguish a hand-written name from a generated one: a plain
        // word, and a word plus a ticket-shaped tag that *is* twelve
        // alphanumerics.
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
        // Deleting a copy of the user's secrets is reported, never silent.
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert!(
            reported[0].contains(&format!("{random}.tmp")),
            "the deletion was not reported: {reported:?}"
        );
    }

    /// Finding 12b, directly on the predicate: a hand-written name must not be
    /// mistaken for a generated one just because it is alphanumeric.
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
        // Not ours at all: another target's prefix, and a non-`.tmp` suffix.
        assert!(!is_generated_temporary(
            format!("other.gitguardian-{ours}.tmp").as_bytes(),
            prefix
        ));
        assert!(!is_generated_temporary(
            format!(".env.gitguardian-{ours}.bak").as_bytes(),
            prefix
        ));
    }

    /// Sanitising the target's name mapped distinct files onto one prefix, and
    /// the sweep then deleted a *live* temporary belonging to another writer,
    /// whose `persist` failed as a result.
    #[test]
    fn two_files_whose_names_differ_only_in_punctuation_get_distinct_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        assert_ne!(
            temporary_prefix(&directory.path().join("a+b.env")),
            temporary_prefix(&directory.path().join("ab.env"))
        );
        // And past the truncation point, where a digest is what keeps them apart.
        let long = "x".repeat(MAX_PREFIX_NAME + 40);
        assert_ne!(
            temporary_prefix(&directory.path().join(format!("{long}-one.env"))),
            temporary_prefix(&directory.path().join(format!("{long}-two.env")))
        );
    }

    /// A leftover holds a full copy of the file, so it must fall under the same
    /// gitignore rule as the file: `.env*` has to catch it.
    #[test]
    fn a_temporary_is_named_after_the_file_it_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let prefix = temporary_prefix(&directory.path().join(".env"));
        assert_eq!(prefix, std::ffi::OsString::from(".env.gitguardian-"));
    }

    /// Finding 5: `yield_now` is not a synchronisation point, so the old shape
    /// of this test passed whether or not the second lock ever blocked — remove
    /// `lock_exclusive` from `lock_sidecar` and both assertions still held.
    ///
    /// A `Barrier` puts the second thread definitely at the lock call, and the
    /// wait below then has to observe it *staying* blocked for long enough that
    /// an unlocked run could not have got through.
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
            // The other thread is now inside `lock_sidecar`. It must still be
            // there in a moment's time, and in the moment after that.
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

    /// Finding 12a: the sidecar gets the same hardening as `LockedFile`.
    ///
    /// A fifo planted at the lock path used to wedge the process inside
    /// `open(2)` — no output, no timeout, nothing to see. On the old `/tmp`
    /// fallback path any local user could plant one and permanently stop every
    /// `set` for that uid.
    #[cfg(unix)]
    #[test]
    fn a_sidecar_lock_refuses_anything_that_is_not_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keyset.lock");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `mkfifo` takes a NUL-terminated path and a mode, and reports
        // failure through its return value.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // The thread is only here to bound the damage if this ever regresses:
        // the whole point is that it returns instead of blocking forever.
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

    /// Finding 3: `replace_bytes` sweeps too.
    ///
    /// It is the writer for the keyring stand-in, so an interrupted run leaves a
    /// temporary holding the base64 **master key**; and since every write to
    /// that file goes through this function, a sweep it does not do is a sweep
    /// nobody does — the leftover sits in the developer's home directory for
    /// good.
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
