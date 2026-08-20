//! `_send_desktop_notification()`: the out-of-band banner raised when a secret
//! has already reached the agent.
//!
//! Best effort: every failure is swallowed, since a missing banner must never
//! cost a verdict. The message quotes a command the agent was about to run, so
//! each backend treats it as data an interpreter never parses.

/// Raise a desktop notification. Never panics, never blocks for long.
///
/// `GGSHIELD_NO_NOTIFICATION` builds the message and delivers nothing: a banner
/// lands on whoever is at the keyboard, and the equivalence gate runs both hooks
/// against payloads carrying secrets.
pub fn send(title: &str, body: &str) {
    if ggshield_config::config::getenv_bool("GGSHIELD_NO_NOTIFICATION") {
        return;
    }
    imp::send(title, body);
}

/// The banner's icon, name and click behaviour all belong to the bundle that
/// posted it, so `osascript` posts as Script Editor. We build and post from a
/// bundle we own instead (`osacompile`, native on every architecture).
///
/// Two macOS constraints shape the rest:
///
/// * a notification is delivered only when LaunchServices started the process,
///   so the applet is launched with `open`, not by running `Contents/MacOS/applet`;
/// * `open --args` does not reach an applet's `on run argv`, and LaunchServices
///   does not forward the environment, so the payload travels through a file.
///
/// The applet consumes that file, which is also what makes a click inert: a
/// click relaunches it, finds no payload, and returns. Permission to post is
/// warmed by `warm_notifier()` during `machine setup`.
#[cfg(target_os = "macos")]
mod imp {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const ICNS: &[u8] = include_bytes!("../assets/ggshield.icns");
    /// Deliberately not `com.gitguardian.ggshield`: that identity belongs to the
    /// signed CLI, and the Keychain ACL keys on its designated requirement.
    const BUNDLE_ID: &str = "com.gitguardian.ggshield.notifier";

    /// `path to me` is the bundle, so `../pending-notification` is the payload
    /// next to it -- no path baked into the script, and nothing written inside
    /// the bundle to break its seal. Reading through `do shell script` keeps the
    /// text a value: a quote in the body is a quote, not the end of a literal.
    const SCRIPT: &str = r#"on run
	set p to (POSIX path of (path to me)) & "../pending-notification"
	set q to quoted form of p
	try
		set t to do shell script "head -1 " & q
		set b to do shell script "tail -n +2 " & q
		do shell script "rm -f " & q
		if t is "" then return
		display notification b with title t
	end try
end run"#;

    pub fn send(title: &str, body: &str) {
        let Some(dir) = ggshield_config::config::cache_dir() else {
            return;
        };
        // Without a bundle there is still a notification to raise; it just wears
        // Script Editor's face.
        let Some(app) = bundle(&dir) else {
            return osascript(title, body);
        };
        // One payload path, so a burst collapses to a single banner: the second
        // write overwrites the first, and `open` on an applet that is still
        // running does not re-enter `on run`.
        if std::fs::write(dir.join("pending-notification"), format!("{title}\n{body}")).is_err() {
            return osascript(title, body);
        }
        let _ = quiet(Command::new("open").arg("-a").arg(&app)).status();
    }

    /// The cached applet, rebuilt when it is missing, stale, or not ours.
    ///
    /// "Stale" means not built from the current script, icon and bundle id, so
    /// the stamp is a digest of those inputs rather than a version. The stamp is
    /// no trust signal: it digests compile-time constants and sits beside the
    /// bundle, so the applet is launched only while the directory holding it is
    /// one no other user can write.
    fn bundle(dir: &Path) -> Option<PathBuf> {
        let app = dir.join("ggshield.app");
        let stamp = dir.join("ggshield.app.stamp");
        let want = fingerprint();
        if app.is_dir()
            && std::fs::read_to_string(&stamp).ok().as_deref() == Some(want.as_str())
            && ggshield_common::secure_file::is_private_dir(dir)
        {
            return Some(app);
        }
        build(dir, &app, &stamp, &want)
    }

    fn fingerprint() -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(SCRIPT.as_bytes());
        h.update(BUNDLE_ID.as_bytes());
        h.update(ICNS);
        format!("{:x}", h.finalize())
    }

    /// Build into a sibling and swap, so a half-written bundle is never the one
    /// `open` finds.
    ///
    /// The scratch name still ends in `.app`: that suffix is what makes
    /// `osacompile` emit a bundle rather than a bare compiled script.
    fn build(dir: &Path, app: &Path, stamp: &Path, want: &str) -> Option<PathBuf> {
        let tmp = dir.join("ggshield.building.app");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(dir).ok()?;
        ok(Command::new("osacompile")
            .arg("-o")
            .arg(&tmp)
            .arg("-e")
            .arg(SCRIPT))?;

        let plist = tmp.join("Contents/Info.plist");
        // osacompile takes CFBundleName from the output filename, so set it
        // explicitly: it is the name the banner and System Settings show.
        plutil(&["-replace", "CFBundleName", "-string", "ggshield"], &plist);
        plutil(
            &["-insert", "CFBundleIdentifier", "-string", BUNDLE_ID],
            &plist,
        );
        plutil(&["-insert", "LSUIElement", "-bool", "true"], &plist);
        // Assets.car wins over applet.icns, and carries osacompile's own icon.
        plutil(&["-remove", "CFBundleIconName"], &plist);
        let _ = std::fs::remove_file(tmp.join("Contents/Resources/Assets.car"));
        std::fs::write(tmp.join("Contents/Resources/applet.icns"), ICNS).ok()?;

        // Those edits break the signature osacompile applied; an ad-hoc one is
        // enough here.
        ok(Command::new("codesign").args(["-f", "-s", "-"]).arg(&tmp))?;

        // `osacompile` and our own writes land under whatever umask we inherited,
        // so drop any group/other write bit before the bundle is trusted.
        harden(&tmp);

        let _ = std::fs::remove_dir_all(app);
        std::fs::rename(&tmp, app).ok()?;
        let _ = std::fs::write(stamp, want);
        Some(app.to_path_buf())
    }

    /// Drop every group and other write bit under `path`.
    fn harden(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut pending = vec![path.to_path_buf()];
        while let Some(path) = pending.pop() {
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_symlink() {
                continue;
            }
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 {
                let _ =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & !0o022));
            }
            if meta.is_dir()
                && let Ok(entries) = std::fs::read_dir(&path)
            {
                pending.extend(entries.flatten().map(|e| e.path()));
            }
        }
    }

    fn plutil(args: &[&str], plist: &Path) {
        let _ = quiet(Command::new("plutil").args(args).arg(plist)).status();
    }

    /// Today's notification, kept as the fallback for anything that stops us
    /// building the bundle. The strings are run-handler arguments rather than
    /// interpolated source: an AppleScript literal cannot hold a quote it does
    /// not own, nor an accent, emoji or tab.
    fn osascript(title: &str, body: &str) {
        let _ = quiet(Command::new("osascript").args([
            "-e",
            "on run argv",
            "-e",
            "display notification (item 1 of argv) with title (item 2 of argv)",
            "-e",
            "end run",
            "--",
            body,
            title,
        ]))
        .status();
    }

    fn ok(cmd: &mut Command) -> Option<()> {
        quiet(cmd).status().ok()?.success().then_some(())
    }

    fn quiet(cmd: &mut Command) -> &mut Command {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// GIVEN a cache directory with no applet in it
        /// WHEN one is built
        /// THEN it is a real bundle wearing our name, id and icon.
        #[test]
        fn the_applet_is_a_bundle_carrying_our_identity() {
            let dir = tempfile::tempdir().expect("tempdir");
            let app = bundle(dir.path()).expect("a bundle");

            assert!(app.is_dir(), "not a bundle: {}", app.display());
            assert!(app.join("Contents/MacOS/applet").is_file());
            assert_eq!(
                std::fs::read(app.join("Contents/Resources/applet.icns")).expect("an icon"),
                ICNS,
                "the bundle does not carry our icon"
            );
            assert!(
                !app.join("Contents/Resources/Assets.car").exists(),
                "Assets.car is left over, and it overrides applet.icns"
            );

            let plist = std::process::Command::new("plutil")
                .args(["-convert", "json", "-o", "-"])
                .arg(app.join("Contents/Info.plist"))
                .output()
                .expect("plutil");
            let plist: serde_json::Value =
                serde_json::from_slice(&plist.stdout).expect("a readable Info.plist");
            assert_eq!(plist["CFBundleIdentifier"], BUNDLE_ID);
            // The name the banner and System Settings show.
            assert_eq!(plist["CFBundleName"], "ggshield");
            // Without this the applet bounces into the Dock on every scan.
            assert_eq!(plist["LSUIElement"], true);
            // Assets.car is gone, so this must point at applet.icns.
            assert_eq!(plist["CFBundleIconFile"], "applet");
            assert!(plist.get("CFBundleIconName").is_none());
        }

        /// GIVEN an applet already built
        /// WHEN a notification is sent again
        /// THEN it is reused rather than recompiled, because `osacompile` and
        /// `codesign` cost far more than the banner itself.
        #[test]
        fn an_existing_applet_is_reused() {
            let dir = tempfile::tempdir().expect("tempdir");
            let app = bundle(dir.path()).expect("a bundle");
            let built = app
                .join("Contents/MacOS/applet")
                .metadata()
                .and_then(|m| m.modified())
                .expect("mtime");

            assert_eq!(bundle(dir.path()).expect("a bundle"), app);
            let after = app
                .join("Contents/MacOS/applet")
                .metadata()
                .and_then(|m| m.modified())
                .expect("mtime");
            assert_eq!(built, after, "the applet was rebuilt");
        }

        /// GIVEN a cached applet whose stamp still matches, in a directory other
        /// users can write to
        /// WHEN a notification is sent
        /// THEN it is rebuilt rather than launched: whoever can write the holding
        /// directory can replace what is inside it, so a matching stamp proves
        /// nothing about who wrote the applet.
        #[test]
        fn an_applet_in_a_directory_others_can_write_is_not_launched() {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().expect("tempdir");
            let app = bundle(dir.path()).expect("a bundle");
            let applet = app.join("Contents/MacOS/applet");
            let planted = b"#!/bin/sh\necho pwned\n";

            // The stamp stays valid: this is what an attacker would leave.
            std::fs::write(&applet, planted).expect("plant");
            let mode = dir.path().metadata().expect("mode").permissions().mode();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode | 0o022))
                .expect("chmod");
            assert_eq!(
                std::fs::read_to_string(dir.path().join("ggshield.app.stamp")).ok(),
                Some(fingerprint()),
                "the stamp must still match, or this tests nothing"
            );

            bundle(dir.path()).expect("a rebuilt bundle");

            assert_ne!(
                std::fs::read(&applet).expect("an applet").as_slice(),
                planted,
                "the planted applet survived and would have been launched"
            );
        }

        /// GIVEN an applet built from a different script or icon
        /// WHEN a notification is sent
        /// THEN it is rebuilt, so a fix to either takes effect without waiting
        /// for a version bump.
        #[test]
        fn a_stale_applet_is_rebuilt() {
            let dir = tempfile::tempdir().expect("tempdir");
            let app = bundle(dir.path()).expect("a bundle");
            std::fs::write(dir.path().join("ggshield.app.stamp"), "from an older build")
                .expect("stamp");
            std::fs::remove_file(app.join("Contents/Resources/applet.icns")).expect("icon");

            bundle(dir.path()).expect("a rebuilt bundle");
            assert_eq!(
                std::fs::read(app.join("Contents/Resources/applet.icns")).expect("an icon"),
                ICNS
            );
        }
    }
}

/// `notify-send` is libnotify's own client. The banner carries the GitGuardian
/// icon rather than a generic one.
#[cfg(target_os = "linux")]
mod imp {
    use std::process::{Command, Stdio};

    pub fn send(title: &str, body: &str) {
        let mut cmd = Command::new("notify-send");
        cmd.arg("--app-name=ggshield");
        if let Some(icon) = super::icon_file() {
            let mut arg = std::ffi::OsString::from("--icon=");
            arg.push(icon);
            cmd.arg(arg);
        }
        // `--` first: the body quotes a command, which can start with a dash.
        let _ = cmd
            .arg("--")
            .arg(title)
            .arg(body)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// A WinRT toast, raised through PowerShell with no extra dependency.
///
/// The toast body is XML and the loader is PowerShell, so the message is written
/// to a file ourselves (escaped) and only its *path* reaches the script. The
/// message must never be interpolated into a PowerShell double-quoted
/// here-string: that expands `$(...)` and would run whatever a command in the
/// message asks.
#[cfg(windows)]
mod imp {
    use std::process::{Command, Stdio};

    /// Reads the document from a path instead of embedding it, so nothing the
    /// message contains is ever parsed as PowerShell.
    const SCRIPT: &str = r#"param([Parameter(Mandatory=$true)][string]$XmlPath)
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml([IO.File]::ReadAllText($XmlPath, [Text.Encoding]::UTF8))
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ggshield').Show($toast)
"#;

    pub fn send(title: &str, body: &str) {
        let Some(dir) = ggshield_config::config::cache_dir() else {
            return;
        };
        let script = dir.join("toast.ps1");
        let doc = dir.join("toast.xml");
        if std::fs::create_dir_all(&dir).is_err()
            || std::fs::write(&script, SCRIPT).is_err()
            || std::fs::write(&doc, document(title, body)).is_err()
        {
            return;
        }
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
            ])
            .arg("-File")
            .arg(&script)
            .arg("-XmlPath")
            .arg(&doc)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn document(title: &str, body: &str) -> String {
        let image = super::icon_file()
            .map(|p| {
                format!(
                    r#"<image placement="appLogoOverride" src="{}"/>"#,
                    escape(&p.to_string_lossy())
                )
            })
            .unwrap_or_default();
        format!(
            r#"<toast><visual><binding template="ToastGeneric">{image}<text>{}</text><text>{}</text></binding></visual></toast>"#,
            escape(title),
            escape(body),
        )
    }

    /// The five XML predefined entities. Without this a `&` or a `<` in a quoted
    /// command makes the document unparseable and the toast never appears.
    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    /// No notifier: notifypy has no backend here either.
    pub fn send(_title: &str, _body: &str) {}
}

/// The icon on disk, written out once from the copy baked into the binary.
///
/// `notify-send` and the toast both want a path, and ggshield is a single
/// executable with no data directory of its own to point at.
#[cfg(any(target_os = "linux", windows))]
fn icon_file() -> Option<std::path::PathBuf> {
    const PNG: &[u8] = include_bytes!("../assets/ggshield.png");
    let dir = ggshield_config::config::cache_dir()?;
    let path = dir.join("ggshield.png");
    // Compared whole, not by length: an icon swapped for another of the same
    // size would otherwise never be put back. It is 28 KB, on a path that only
    // runs when a secret has already leaked.
    if std::fs::read(&path).ok().as_deref() == Some(PNG) {
        return Some(path);
    }
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(&path, PNG).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    /// GIVEN a host with a desktop session
    /// WHEN a notification is sent
    /// THEN it appears, wearing the GitGuardian icon, and clicking it does
    /// nothing.
    ///
    /// Ignored by default: it raises a real banner, which no CI runner can
    /// assert on and no developer wants from `cargo test`. Run it by hand with
    /// `cargo test -p ggshield-hook -- --ignored raises_a_real_notification`.
    #[test]
    #[ignore = "raises a real desktop notification; verify it by eye"]
    fn raises_a_real_notification() {
        super::send(
            "ggshield - Secrets Detected",
            "Cursor got access to 1 secret by running the command `printenv \"café\" ❤`",
        );
    }

    /// Serialises the environment this test owns.
    static NOTIFY_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// GIVEN `GGSHIELD_NO_NOTIFICATION` is set
    /// WHEN a notification is sent
    /// THEN nothing is delivered and nothing is built to deliver it with, for
    /// every value the switch reads as true.
    #[test]
    fn the_no_notification_switch_delivers_nothing() {
        let _guard = NOTIFY_ENV.lock().unwrap_or_else(|e| e.into_inner());
        for value in ["1", "true", "TRUE", "yes", ""] {
            let dir = tempfile::tempdir().expect("tempdir");
            // SAFETY: single-threaded section, serialised by the guard above.
            unsafe {
                std::env::set_var("GGSHIELD_NO_NOTIFICATION", value);
                std::env::set_var("GG_CACHE_DIR", dir.path());
            }
            super::send("ggshield - Secrets Detected", "nothing should appear");
            unsafe {
                std::env::remove_var("GGSHIELD_NO_NOTIFICATION");
                std::env::remove_var("GG_CACHE_DIR");
            }
            let left: Vec<_> = std::fs::read_dir(dir.path())
                .expect("read")
                .filter_map(|e| e.ok().map(|e| e.file_name()))
                .collect();
            assert!(
                left.is_empty(),
                "{value:?} suppresses delivery, yet left {left:?}"
            );
        }
    }
}
