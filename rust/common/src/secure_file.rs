//! Cache files only the current user could have written: no symlink, no other
//! owner, no group- or other-writable bit, mode 0600.
//!
//! This only rules out *other* users: anyone who can write as the current uid
//! could equally replace the binary.
//!
//! What a failure *means* is the caller's business — the clean-verdict cache fails
//! closed and scans, the limits cache falls through to the next source.

use std::io::{Read, Write};
use std::path::Path;

/// Create the cache directory, private to us, if it is not there already.
pub fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// `path`'s contents, or `None` when it is not a file only we could have written.
pub fn read_if_trusted(path: &Path) -> Option<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        // A symlink is not a file we wrote.
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    // Check the open descriptor, not the path: no window in which the file we
    // validated could be swapped for the file we read.
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Group/other-writable, or written by somebody else. Unix-only, as in the
        // Python: Windows reports these bits set on every file.
        // SAFETY: `getuid` is a plain syscall wrapper and cannot fail.
        if meta.mode() & 0o022 != 0 || meta.uid() != unsafe { libc::getuid() } {
            return None;
        }
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw).ok()?;
    Some(raw)
}

/// Write `contents` to `path`, readable and writable by us alone. Truncates in
/// place, so a caller that cannot afford a torn read stages and renames.
pub fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        // The creation mode only applies to a file we created. Force it, so a
        // pre-existing loose-permission file — which `read_if_trusted` refuses —
        // does not disable the cache for good.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GIVEN a file we wrote ourselves
    /// WHEN it is read back
    /// THEN it is trusted, and it is ours alone to read and write.
    #[test]
    fn a_file_we_wrote_is_trusted_and_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.json");
        write_private(&path, "payload").expect("write");
        assert_eq!(read_if_trusted(&path).as_deref(), Some("payload"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// GIVEN a file another local user could write, or a symlink, or a directory
    /// WHEN it is read
    /// THEN it is refused, and the next write repairs the permissions.
    #[cfg(unix)]
    #[test]
    fn a_widely_writable_or_symlinked_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.json");
        write_private(&path, "payload").expect("write");
        for mode in [0o660, 0o606, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(
                read_if_trusted(&path).is_none(),
                "{mode:o} must not be trusted"
            );
        }
        write_private(&path, "payload").expect("write");
        assert!(read_if_trusted(&path).is_some());

        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(read_if_trusted(&link).is_none());
        assert!(write_private(&link, "payload").is_err());

        assert!(read_if_trusted(dir.path()).is_none());
    }

    /// GIVEN a cache directory that does not exist yet
    /// WHEN it is created
    /// THEN it is ours alone, and creating it again is not an error.
    #[test]
    fn the_cache_dir_is_created_private_and_idempotently() {
        let parent = tempfile::tempdir().expect("tempdir");
        let dir = parent.path().join("nested/cache");
        create_dir_private(&dir).expect("create");
        create_dir_private(&dir).expect("create again");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
}
