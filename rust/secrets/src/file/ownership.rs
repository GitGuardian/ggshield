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
