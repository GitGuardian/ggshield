//! File ACLs on Windows, where `std::fs::Permissions` is only the read-only flag.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree, WIN32_ERROR};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetTokenInformation,
    NO_INHERITANCE, OBJECT_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A file's DACL, captured from an open handle so a later path swap cannot change it.
pub(crate) struct Dacl {
    /// Owns the memory `acl` points into.
    descriptor: PSECURITY_DESCRIPTOR,
    acl: *mut ACL,
    protected: bool,
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by GetSecurityInfo, freed exactly once.
        unsafe { LocalFree(self.descriptor) };
    }
}

impl Dacl {
    pub(crate) fn of(file: &File) -> io::Result<Self> {
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: out-pointers are valid; the handle is open for the duration of the call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        check(status)?;
        let mut dacl = Dacl {
            descriptor,
            acl,
            protected: false,
        };
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `descriptor` is the valid descriptor returned above.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        dacl.protected = control & SE_DACL_PROTECTED != 0;
        Ok(dacl)
    }

    #[cfg(test)]
    pub(crate) fn is_protected(&self) -> bool {
        self.protected
    }

    /// An unprotected DACL keeps inheriting from the new file's directory, as the original did.
    pub(crate) fn apply_to(&self, path: &Path) -> io::Result<()> {
        let inheritance = if self.protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        set_dacl(path, self.acl, inheritance)
    }
}

/// Replace `path`'s DACL with one granting the current user alone, inheriting nothing.
pub(crate) fn restrict_to_current_user(path: &Path) -> io::Result<()> {
    let user = CurrentUser::query()?;
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user.sid().cast(),
        },
    };
    let mut acl = null_mut();
    // SAFETY: one valid entry whose SID outlives the call; `acl` receives a LocalAlloc'd ACL.
    check(unsafe { SetEntriesInAclW(1, &access, null(), &mut acl) })?;
    let result = set_dacl(path, acl, PROTECTED_DACL_SECURITY_INFORMATION);
    // SAFETY: allocated by SetEntriesInAclW, freed exactly once.
    unsafe { LocalFree(acl.cast()) };
    result
}

fn set_dacl(path: &Path, acl: *const ACL, extra: OBJECT_SECURITY_INFORMATION) -> io::Result<()> {
    let wide = wide(path);
    // SAFETY: `wide` is NUL-terminated and `acl` is valid (or null, a null DACL) for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | extra,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    check(status)
}

/// The process token's `TOKEN_USER`, in a buffer aligned for it.
struct CurrentUser {
    buffer: Vec<u64>,
}

impl CurrentUser {
    fn query() -> io::Result<Self> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo-handle needs no closing; `token` receives a real handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self::from_token(token);
        // SAFETY: opened above, closed exactly once.
        unsafe { CloseHandle(token) };
        result
    }

    fn from_token(token: HANDLE) -> io::Result<Self> {
        let mut needed = 0u32;
        // SAFETY: a size query with no buffer; failure with a size is the expected outcome.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buffer` holds at least `needed` bytes.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(CurrentUser { buffer })
    }

    fn sid(&self) -> PSID {
        // SAFETY: the buffer was filled with a TOKEN_USER and is 8-byte aligned.
        unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_restricted_file_keeps_a_protected_dacl_through_a_copy() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::write(&original, "").unwrap();
        restrict_to_current_user(&original).unwrap();

        let dacl = Dacl::of(&File::open(&original).unwrap()).unwrap();
        assert!(dacl.protected, "the restricted DACL must not inherit");

        let copy = directory.path().join("copy");
        std::fs::write(&copy, "").unwrap();
        dacl.apply_to(&copy).unwrap();
        let copied = Dacl::of(&File::open(&copy).unwrap()).unwrap();
        assert!(copied.protected, "the copy lost the original's protection");
    }
}
