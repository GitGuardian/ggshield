//! `secret.ignored_paths`: which files a scan never reads.
//!
//! Port of `core/filter.py`'s `translate_user_pattern()` /
//! `init_exclusion_regexes()` and `utils/files.py`'s `is_path_excluded()`.
//! `add_secret_scan_common_options()` unions the user's globs with
//! `IGNORED_DEFAULT_WILDCARDS` for every `secret scan` command, so the hook
//! does too.

use std::path::Path;

use regex::Regex;

use ggshield_config::user_config::SecretConfig;

/// `IGNORED_DEFAULT_WILDCARDS`, in `cmd/secret/scan/secret_scan_common_options.py`.
const IGNORED_DEFAULT_WILDCARDS: [&str; 14] = [
    "**/.git/*/**/*",
    "**/.pytest_cache/**/*",
    "**/.mypy_cache/**/*",
    "**/.venv/**/*",
    "**/.eggs/**/*",
    "**/.eggs-info/**/*",
    "**/vendor/**/*",
    "**/vendors/**/*",
    "**/node_modules/**/*",
    "top-1000.txt*",
    "**/*.storyboard*",
    "**/*.xib",
    "**/*.mdx*",
    "**/*.sops",
];

/// `REGEX_SPECIAL_CHARS`. `*` is escaped here and unescaped by the two
/// substitutions below, as Python does it.
const REGEX_SPECIAL_CHARS: &str = ".^$+*?{}()[]\\|";

/// The compiled `secret.ignored_paths`, ready to test paths against.
#[derive(Debug, Default)]
pub struct Exclusions {
    /// The user's own globs, tested against the identifier as it reaches us.
    user: Vec<Regex>,
    /// `IGNORED_DEFAULT_WILDCARDS`, tested project-relative — see `is_excluded`.
    default: Vec<Regex>,
}

impl Exclusions {
    /// Compile the user's globs and the default wildcards.
    ///
    /// Diverges from Python on an invalid pattern: Python raises `UsageError`,
    /// which here would fail every event closed over a typo. Dropping the glob
    /// scans more, not less.
    pub fn new(secret_config: &SecretConfig) -> Self {
        Exclusions {
            user: compile(secret_config.ignored_paths.iter().map(String::as_str)),
            default: compile(IGNORED_DEFAULT_WILDCARDS.into_iter()),
        }
    }

    /// `is_path_excluded()` for the file a Read names, in a project rooted at
    /// `cwd`.
    ///
    /// The user's globs are tested against the identifier itself, which is what
    /// their config was written about. The default wildcards are tested against
    /// the path *relative to the project*, and with symlinks resolved: they name
    /// vendored and cache trees inside a checkout, so against an absolute path
    /// they also match on an ancestor outside it — a checkout under `~/vendor/`
    /// would have every read excluded — and on the name of a link parked in
    /// `node_modules/` that points anywhere at all. Both diverge from Python's
    /// hook, which tests the identifier as given; see `known_divergences` in
    /// tests/equivalence.py.
    ///
    /// Python's directory branch (a trailing `/`, so a directory pattern can
    /// match) is not reproduced: the hook only asks about files a tool named.
    #[must_use]
    pub fn is_excluded(&self, path: &str, cwd: &str) -> bool {
        if self.user.iter().any(|regex| regex.is_match(&posix(path))) {
            return true;
        }
        let relative = project_relative(path, cwd);
        self.default.iter().any(|regex| regex.is_match(&relative))
    }
}

fn compile<'a>(patterns: impl Iterator<Item = &'a str>) -> Vec<Regex> {
    patterns
        .filter(|pattern| is_pattern_valid(pattern))
        .filter_map(|pattern| Regex::new(&translate_user_pattern(pattern)).ok())
        .collect()
}

/// `path` with the separators the patterns are written with. Only Windows has
/// `\` as a separator; on POSIX it is an ordinary filename character, which is
/// why `PurePosixPath` leaves it alone there.
#[cfg(windows)]
fn posix(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(not(windows))]
fn posix(path: &str) -> String {
    path.to_string()
}

/// `path` relative to `cwd`, symlinks resolved. Falls back to `path` itself when
/// there is no cwd, when the file is gone, or when it resolves outside the
/// project — there is no project-relative form then.
fn project_relative(path: &str, cwd: &str) -> String {
    let real = |raw: &str| {
        std::fs::canonicalize(raw)
            .map(|resolved| resolved.to_string_lossy().into_owned())
            .unwrap_or_else(|_| raw.to_string())
    };
    let resolved = real(path);
    if cwd.is_empty() {
        return posix(&resolved);
    }
    // Component-wise, so a sibling directory sharing a name prefix with the
    // project is not mistaken for being inside it.
    let relative = Path::new(&resolved)
        .strip_prefix(real(cwd))
        .map(|rest| rest.to_string_lossy().into_owned())
        .unwrap_or(resolved);
    posix(&relative)
}

/// `is_pattern_valid()`: `***` is never valid, and a `**` must be a whole path
/// segment.
fn is_pattern_valid(pattern: &str) -> bool {
    if pattern.is_empty() || pattern.contains("***") {
        return false;
    }
    let bytes = pattern.as_bytes();
    for (index, window) in bytes.windows(2).enumerate() {
        if window != b"**" {
            continue;
        }
        // A "**" must be immediately followed by a "/" ...
        if bytes.get(index + 2).is_some_and(|byte| *byte != b'/') {
            return false;
        }
        // ... and be at the start, or immediately preceded by a "/".
        if index > 0 && bytes[index - 1] != b'/' {
            return false;
        }
    }
    true
}

/// `translate_user_pattern()`: a glob to the regex Python compiles for it.
fn translate_user_pattern(pattern: &str) -> String {
    let mut escaped = String::with_capacity(pattern.len() * 2);
    for character in pattern.chars() {
        if REGEX_SPECIAL_CHARS.contains(character) {
            escaped.push('\\');
        }
        escaped.push(character);
    }

    // Anchor the end unless the pattern names a directory, and the start only
    // when the pattern is absolute; otherwise it may begin at any segment.
    if !escaped.ends_with('/') {
        escaped.push('$');
    }
    let mut translated = if let Some(rest) = escaped.strip_prefix('/') {
        format!("^{rest}")
    } else {
        format!("(^|/){escaped}")
    };

    // Order matters: "**/" first, so the "*" rule cannot eat half of one.
    translated = translated.replace("\\*\\*/", "([^/]+/)*");
    translated.replace("\\*", "([^/]+)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exclusions(patterns: &[&str]) -> Exclusions {
        Exclusions::new(&SecretConfig {
            ignored_paths: patterns.iter().map(|p| (*p).to_string()).collect(),
            ..SecretConfig::default()
        })
    }

    /// GIVEN the globs Python's own tests translate
    /// WHEN they are translated here
    /// THEN the regex is `translate_user_pattern()`'s, character for character.
    #[test]
    fn the_translation_is_the_python_one() {
        for (pattern, expected) in [
            ("tests/fixtures/**", "(^|/)tests/fixtures/([^/]+)([^/]+)$"),
            ("**/tmp/**", "(^|/)([^/]+/)*tmp/([^/]+)([^/]+)$"),
            ("/rooted/path", "^rooted/path$"),
            ("a directory/", "(^|/)a directory/"),
            ("**/*.sops", "(^|/)([^/]+/)*([^/]+)\\.sops$"),
            ("top-1000.txt*", "(^|/)top-1000\\.txt([^/]+)$"),
        ] {
            assert_eq!(translate_user_pattern(pattern), expected, "{pattern}");
        }
    }

    /// GIVEN patterns Python's `is_pattern_valid()` rejects
    /// WHEN they are validated
    /// THEN they are rejected here too.
    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in ["", "a***b", "a**/b", "**a/b", "x/**y"] {
            assert!(!is_pattern_valid(bad), "{bad} should be invalid");
        }
        for good in ["**/a", "a/**/b", "a/**", "*.py", "/rooted"] {
            assert!(is_pattern_valid(good), "{good} should be valid");
        }
    }

    /// GIVEN a glob written relative to the repo
    /// WHEN an absolute path is tested, as the hook always gets from an agent
    /// THEN it still matches: the translation anchors on `(^|/)`.
    #[test]
    fn a_relative_glob_matches_an_absolute_path() {
        let excluded = exclusions(&["tests/fixtures/**"]);
        assert!(excluded.is_excluded("tests/fixtures/creds.py", ""));
        assert!(excluded.is_excluded("/home/me/repo/tests/fixtures/creds.py", ""));
        assert!(!excluded.is_excluded("/home/me/repo/src/creds.py", ""));
    }

    /// GIVEN a trailing `**`, which Python expands to `([^/]+)([^/]+)$`
    /// WHEN a nested path is tested
    /// THEN it does NOT match: a trailing `**` spans one segment only. Python's
    /// quirk, pinned so the two agree.
    #[test]
    fn a_trailing_double_star_spans_one_segment_as_in_python() {
        let excluded = exclusions(&["tests/fixtures/**"]);
        assert!(excluded.is_excluded("tests/fixtures/creds.py", ""));
        assert!(!excluded.is_excluded("tests/fixtures/sub/creds.py", ""));
        assert!(!excluded.is_excluded("/abs/tests/fixtures/sub/creds.py", ""));
    }

    /// GIVEN a Windows path
    /// WHEN it is tested against a glob written with forward slashes
    /// THEN it matches, because `\` is a separator there and is normalized first.
    #[cfg(windows)]
    #[test]
    fn a_windows_path_matches_a_posix_glob() {
        assert!(
            exclusions(&["tests/fixtures/**"])
                .is_excluded(r"C:\Users\me\repo\tests\fixtures\creds.py", "")
        );
    }

    /// GIVEN a POSIX filename containing backslashes
    /// WHEN it is tested against the default wildcards
    /// THEN they do not match: there `\` is an ordinary filename character, and
    /// `PurePosixPath` leaves it alone, so Python scans this file too.
    #[cfg(not(windows))]
    #[test]
    fn backslashes_are_ordinary_characters_on_posix() {
        let excluded = exclusions(&[]);
        assert!(!excluded.is_excluded(r"/repo/node_modules\pkg\x.py", "/repo"));
        assert!(!excluded.is_excluded(r"node_modules\pkg\x.py", ""));
        assert!(excluded.is_excluded("/repo/node_modules/pkg/x.py", "/repo"));
    }

    /// GIVEN no user config at all
    /// WHEN a vendored path inside the project is tested
    /// THEN the default wildcards still exclude it.
    #[test]
    fn the_default_wildcards_apply_without_any_user_config() {
        let excluded = exclusions(&[]);
        assert!(excluded.is_excluded("/repo/node_modules/pkg/creds.py", "/repo"));
        assert!(excluded.is_excluded("/repo/.venv/lib/thing.py", "/repo"));
        assert!(!excluded.is_excluded("/repo/src/creds.py", "/repo"));
    }

    /// GIVEN a project whose own path runs through a vendor-like directory
    /// WHEN a file inside it is tested
    /// THEN the default wildcards do not match: they are tested relative to the
    /// project, so an ancestor outside it cannot exclude the whole checkout.
    #[test]
    fn the_default_wildcards_ignore_ancestors_above_the_project() {
        let excluded = exclusions(&[]);
        for root in [
            "/home/me/vendor/proj",
            "/home/me/node_modules/proj",
            "/home/me/.venv/proj",
        ] {
            assert!(
                !excluded.is_excluded(&format!("{root}/src/creds.env"), root),
                "{root}"
            );
            // ...and a vendored tree *inside* the project still is.
            assert!(
                excluded.is_excluded(&format!("{root}/vendor/lib/creds.env"), root),
                "{root}"
            );
        }
    }

    /// GIVEN a user glob naming a directory the project itself sits under
    /// WHEN a file inside the project is tested
    /// THEN it is excluded: the user's own globs are tested against the
    /// identifier as written, exactly as every other `secret scan` does.
    #[test]
    fn a_user_glob_still_matches_anywhere_in_the_path() {
        let excluded = exclusions(&["**/vendor/**/*"]);
        assert!(excluded.is_excluded("/home/me/vendor/proj/src/creds.env", "/home/me/vendor/proj"));
    }

    /// GIVEN a symlink parked in `node_modules` pointing outside it
    /// WHEN the link is read
    /// THEN it is not excluded: the default wildcards are tested against where
    /// the bytes live, so a link cannot hide a file behind an excluded name.
    ///
    /// Unix only: creating a symlink on Windows needs a privilege a test runner
    /// is not guaranteed to have.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_a_vendored_tree_is_not_excluded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("node_modules/.cache")).expect("mkdir");
        let outside = root.join("credentials");
        std::fs::write(&outside, "TOKEN=abc").expect("write");
        let link = root.join("node_modules/.cache/x");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        let excluded = exclusions(&[]);
        let cwd = root.to_string_lossy();
        assert!(!excluded.is_excluded(&link.to_string_lossy(), &cwd));

        // A real file in the same tree stays excluded.
        let real = root.join("node_modules/pkg/creds.env");
        std::fs::create_dir_all(real.parent().expect("parent")).expect("mkdir");
        std::fs::write(&real, "TOKEN=abc").expect("write");
        assert!(excluded.is_excluded(&real.to_string_lossy(), &cwd));
    }

    /// GIVEN one unparseable glob among good ones
    /// WHEN the set is compiled
    /// THEN the bad one is dropped and the rest still exclude.
    #[test]
    fn a_bad_glob_is_dropped_rather_than_fatal() {
        let excluded = exclusions(&["a***b", "tests/fixtures/**"]);
        assert!(excluded.is_excluded("/repo/tests/fixtures/creds.py", ""));
        assert!(!excluded.is_excluded("/repo/a-b", ""));
    }
}
