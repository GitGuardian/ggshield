//! Who could have written a file this process is about to load, as git's `safe.directory`.

use std::path::Path;

/// Git's rule: the current user, or on Windows the Administrators group when this process
/// is elevated. Unreadable metadata is not ownership.
#[cfg(unix)]
pub(crate) fn is_owned_by_current_user(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    std::fs::metadata(path).is_ok_and(|metadata| metadata.uid() == euid)
}

#[cfg(windows)]
pub(crate) fn is_owned_by_current_user(path: &Path) -> bool {
    use super::win_security::{Owner, is_administrator, owner_of};
    match owner_of(path) {
        Ok(Owner::CurrentUser) => true,
        Ok(Owner::Administrators) => is_administrator().unwrap_or(false),
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn is_owned_by_current_user(_path: &Path) -> bool {
    true
}

/// Why another non-administrator could have written `path`, or `None` when only root (an
/// administrator or SYSTEM on Windows) or the current user could have. Unreadable metadata
/// gives `None`: the read that follows reports it.
#[cfg(unix)]
pub(crate) fn untrusted_writer(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != 0 && metadata.uid() != euid {
        return Some(format!(
            "{} is owned by another user (uid {}), not root",
            path.display(),
            metadata.uid()
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Some(format!(
            "{} is writable by users other than its owner",
            path.display()
        ));
    }
    None
}

#[cfg(windows)]
pub(crate) fn untrusted_writer(path: &Path) -> Option<String> {
    use super::win_security::{Owner, owner_of};
    match owner_of(path) {
        Ok(Owner::CurrentUser | Owner::Administrators | Owner::System) => None,
        Ok(Owner::Other) => Some(format!(
            "{} is not owned by an administrator",
            path.display()
        )),
        Err(error) => Some(format!("cannot tell who owns {}: {error}", path.display())),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn untrusted_writer(_path: &Path) -> Option<String> {
    None
}
