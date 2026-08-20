//! `.gitguardian.yaml` loading. Mirrors `UserConfig.load()` (user_config.py),
//! `convert_v1_config_dict()` (v1_config.py) and the discovery helpers in
//! `ggshield/core/config/utils.py`.
//!
//! A key that would change behaviour but is NOT implemented makes the hook
//! decline and fail open with a warning. Declining scans NOTHING, silently, where
//! scanning with a rule missing scans MORE, noisily — which is why a v1 config
//! (and a versionless file IS v1) is converted rather than refused.
//!
//! Keys treated as no-ops, because they do not reach this path:
//!   secret.show_secrets           the hook always censors (`censor_match`)
//!   secret.with_incident_details  only adds a token scope to the API-key
//!                                 precheck, which this binary skips
//!   secret.prereceive_remediation_message, secret.fail_on_server_error,
//!   max_commits_for_hook, verbose, debug     other commands only

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use ggshield_common::error::Error;

pub const USER_CONFIG_FILENAMES: [&str; 3] =
    [".gitguardian", ".gitguardian.yml", ".gitguardian.yaml"];
const CURRENT_CONFIG_VERSION: i64 = 2;

#[derive(Debug, Default, Clone)]
pub struct SecretConfig {
    /// Each entry is either the sha256 "ignore sha" of a policy break or a
    /// literal secret value; `is_in_ignored_matches` accepts both.
    pub ignored_matches: Vec<String>,
    pub ignored_detectors: BTreeSet<String>,
    /// Globs, as written in the file. Compiled by `ggshield_hook::exclusion`,
    /// which also adds the default wildcards.
    pub ignored_paths: Vec<String>,
    pub ignore_known_secrets: bool,
    /// When true, ignored secrets are still reported — so they still block.
    pub all_secrets: bool,
    pub filename_only: bool,
}

#[derive(Debug, Default, Clone)]
pub struct UserConfig {
    pub instance: Option<String>,
    pub exit_zero: bool,
    /// Disables TLS certificate verification for the API client (v1
    /// `allow_self_signed`). Off by default; see `api.rs`.
    pub insecure: bool,
    pub secret: SecretConfig,
}

/// A `.gitguardian.yaml` as written, before the files are merged.
///
/// Both spellings of every key are accepted through `alias`, with one intentional
/// divergence: given the *same* key in both spellings Python keeps the underscored
/// one (`replace_dash_in_keys`), while here the last spelling in the file wins.
///
/// Scalars are `Option` so "unset" and "set to the default" stay distinct across
/// the global/local merge, and an explicit `null` reads as unset the way
/// `update_dict_from_other()` treats it.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawUserConfig {
    instance: Option<String>,
    #[serde(alias = "exit-zero")]
    exit_zero: Option<bool>,
    /// `_fix_allow_self_signed()`: the v1 spelling is the same setting.
    #[serde(alias = "allow_self_signed", alias = "allow-self-signed")]
    insecure: Option<bool>,
    /// `_fix_ignore_known_secrets()`: originally accepted at the root, where it
    /// still works unless `secret` gives its own value.
    #[serde(alias = "ignore-known-secrets")]
    ignore_known_secrets: Option<bool>,
    secret: RawSecretConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSecretConfig {
    #[serde(alias = "ignored-matches")]
    ignored_matches: Vec<IgnoredMatch>,
    #[serde(alias = "ignored-detectors")]
    ignored_detectors: BTreeSet<String>,
    #[serde(alias = "ignored-paths")]
    ignored_paths: Vec<String>,
    #[serde(alias = "ignore-known-secrets")]
    ignore_known_secrets: Option<bool>,
    #[serde(alias = "all-secrets")]
    all_secrets: Option<bool>,
    #[serde(alias = "filename-only")]
    filename_only: Option<bool>,
}

/// One `secret.ignored_matches` entry. `name` is never compared, so it is not read
/// here; a missing `match` is a config error in Python too.
#[derive(Debug, Deserialize)]
struct IgnoredMatch {
    #[serde(rename = "match")]
    value: String,
}

/// A v1 (legacy) `.gitguardian.yaml`, i.e. anything without `version: 2`. The
/// deprecation messages Python prints for `all_policies` and
/// `ignore_default_excludes` are not reproduced; they change no behaviour.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct V1Config {
    #[serde(alias = "matches-ignore")]
    matches_ignore: Vec<V1IgnoredMatch>,
    #[serde(alias = "banlisted-detectors")]
    banlisted_detectors: BTreeSet<String>,
    #[serde(alias = "paths-ignore")]
    paths_ignore: Vec<String>,
    #[serde(alias = "api-url")]
    api_url: Option<String>,
    #[serde(alias = "allow-self-signed")]
    allow_self_signed: Option<bool>,
    #[serde(alias = "exit-zero")]
    exit_zero: Option<bool>,
    instance: Option<String>,
}

/// `_convert_matches_ignore_entry()`: v1 allowed a bare ignore sha where v2 wants
/// `{name, match}`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum V1IgnoredMatch {
    Sha(String),
    Entry(IgnoredMatch),
}

/// Just the `version` key, read before deciding which schema the rest follows.
#[derive(Debug, Default, Deserialize)]
struct ConfigVersion {
    #[serde(default)]
    version: Option<i64>,
}

impl From<V1Config> for RawUserConfig {
    fn from(v1: V1Config) -> Self {
        // "api_url" becomes "instance", but never overwrites an explicit one.
        let instance = v1.instance.or_else(|| {
            v1.api_url
                .as_deref()
                .map(crate::config::api_to_dashboard_url)
        });
        RawUserConfig {
            instance,
            exit_zero: v1.exit_zero,
            insecure: v1.allow_self_signed,
            ignore_known_secrets: None,
            secret: RawSecretConfig {
                ignored_matches: v1
                    .matches_ignore
                    .into_iter()
                    .map(|entry| match entry {
                        V1IgnoredMatch::Sha(sha) => IgnoredMatch { value: sha },
                        V1IgnoredMatch::Entry(entry) => entry,
                    })
                    .collect(),
                ignored_detectors: v1.banlisted_detectors,
                // `copy_if_set(secret_dct, "ignored_paths", "paths_ignore")`.
                ignored_paths: v1.paths_ignore,
                ..RawSecretConfig::default()
            },
        }
    }
}

impl RawUserConfig {
    /// `update_dict_from_other()`: ignore lists accumulate across files, scalars
    /// are overwritten by the later file, and a key the later file leaves unset
    /// keeps the earlier value.
    fn merge(&mut self, later: RawUserConfig) {
        self.instance = later.instance.or_else(|| self.instance.take());
        self.exit_zero = later.exit_zero.or(self.exit_zero);
        self.insecure = later.insecure.or(self.insecure);
        self.ignore_known_secrets = later.ignore_known_secrets.or(self.ignore_known_secrets);

        let secret = &mut self.secret;
        secret.ignored_matches.extend(later.secret.ignored_matches);
        secret
            .ignored_detectors
            .extend(later.secret.ignored_detectors);
        secret.ignored_paths.extend(later.secret.ignored_paths);
        secret.ignore_known_secrets = later
            .secret
            .ignore_known_secrets
            .or(secret.ignore_known_secrets);
        secret.all_secrets = later.secret.all_secrets.or(secret.all_secrets);
        secret.filename_only = later.secret.filename_only.or(secret.filename_only);
    }

    fn resolve(self) -> Result<UserConfig, Error> {
        Ok(UserConfig {
            instance: self
                .instance
                .map(|url| url.trim_end_matches('/').to_string()),
            exit_zero: self.exit_zero.unwrap_or_default(),
            insecure: self.insecure.unwrap_or_default(),
            secret: SecretConfig {
                ignored_matches: self
                    .secret
                    .ignored_matches
                    .into_iter()
                    .map(|entry| entry.value)
                    .collect(),
                ignored_detectors: self.secret.ignored_detectors,
                ignored_paths: self.secret.ignored_paths,
                ignore_known_secrets: self
                    .secret
                    .ignore_known_secrets
                    .or(self.ignore_known_secrets)
                    .unwrap_or_default(),
                all_secrets: self.secret.all_secrets.unwrap_or_default(),
                filename_only: self.secret.filename_only.unwrap_or_default(),
            },
        })
    }
}

pub fn home_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("GG_USER_HOME_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir()
}

fn first_existing(dir: &Path) -> Option<PathBuf> {
    USER_CONFIG_FILENAMES
        .iter()
        .map(|name| dir.join(name))
        .find(|path| path.exists())
}

pub fn global_config_path() -> Option<PathBuf> {
    first_existing(&home_dir()?)
}

/// `get_project_root_dir(Path())`: the git worktree root, or the cwd when this is
/// not a git checkout. Python shells out to `git rev-parse --show-toplevel`;
/// walking up to the nearest `.git` (a file too, as linked worktrees mark their
/// root) gives the same answer without a subprocess.
pub fn project_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    for ancestor in cwd.ancestors() {
        if ancestor.join(".git").exists() {
            return ancestor.to_path_buf();
        }
    }
    cwd
}

/// `find_local_config_path()`. Note it looks ONLY at the project root — a
/// `.gitguardian.yaml` sitting in an intermediate directory between the root and
/// the cwd is invisible to ggshield, so it must be invisible here too.
pub fn local_config_path() -> Option<PathBuf> {
    first_existing(&project_root())
}

/// An empty document deserializes as `None`, which is the default config.
fn parse_yaml<T>(raw: &str, path: &Path) -> Result<T, Error>
where
    T: Default + serde::de::DeserializeOwned,
{
    serde_yaml_ng::from_str::<Option<T>>(raw)
        .map(Option::unwrap_or_default)
        .map_err(|e| Error::fatal(format!("{}: {e}", path.display())))
}

/// `_load_config_dict()` for one file.
fn load_config_file(path: &Path) -> Result<RawUserConfig, Error> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::fatal(format!("{}: {e}", path.display())))?;
    // A missing `version` means 1: Python warns and converts rather than reject,
    // so declining here would disable scanning for every pre-`version` config.
    let version = parse_yaml::<ConfigVersion>(&raw, path)?
        .version
        .unwrap_or(1);
    match version {
        CURRENT_CONFIG_VERSION => parse_yaml(&raw, path),
        1 => parse_yaml::<V1Config>(&raw, path).map(Into::into),
        // `raise UnexpectedError`, which reaches the hook's fail-open handler.
        other => Err(Error::fatal(format!(
            "Don't know how to load config version {other}"
        ))),
    }
}

/// Loads the global config then the local one, merged as Python merges them.
pub fn load() -> Result<UserConfig, Error> {
    let mut merged = RawUserConfig::default();
    for path in [global_config_path(), local_config_path()]
        .into_iter()
        .flatten()
    {
        merged.merge(load_config_file(&path)?);
    }
    merged.resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<UserConfig, Error> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(".gitguardian.yaml");
        std::fs::write(&path, yaml).expect("write");
        load_config_file(&path)?.resolve()
    }

    /// GIVEN a v2 config setting every key the hook reads
    /// WHEN it is loaded
    /// THEN each one reaches the resolved config.
    #[test]
    fn reads_every_key_that_reaches_the_hook_path() {
        let config = parse(
            "version: 2\ninstance: https://gg.example.com\nexit_zero: true\nsecret:\n  \
             ignored_detectors: [Generic Password, AWS Keys]\n  ignore_known_secrets: true\n  \
             all_secrets: true\n  filename_only: true\n  ignored_matches:\n  - match: abcdef\n    \
             name: a\n  - match: fedcba\n",
        )
        .expect("parses");
        assert_eq!(config.instance.as_deref(), Some("https://gg.example.com"));
        assert!(config.exit_zero);
        assert_eq!(config.secret.ignored_matches, vec!["abcdef", "fedcba"]);
        assert!(config.secret.ignored_detectors.contains("AWS Keys"));
        assert!(config.secret.ignore_known_secrets);
        assert!(config.secret.all_secrets);
        assert!(config.secret.filename_only);
    }

    /// GIVEN keys that do not reach the ai-hook path
    /// WHEN the config is loaded
    /// THEN they are accepted and ignored rather than rejected.
    #[test]
    fn keys_that_do_not_reach_this_path_are_accepted_and_ignored() {
        let config = parse(
            "version: 2\nsecret:\n  show_secrets: true\n  \
             with_incident_details: true\n  fail_on_server_error: false\nverbose: true\n",
        )
        .expect("parses");
        assert!(config.secret.ignored_matches.is_empty());
        assert!(!config.secret.all_secrets);
    }

    /// GIVEN `secret.ignored_paths`, in v2 and in the v1 `paths_ignore` spelling
    /// WHEN the config is loaded
    /// THEN both reach `SecretConfig`, where the hook compiles them.
    #[test]
    fn ignored_paths_are_read_from_both_schemas() {
        assert_eq!(
            parse("version: 2\nsecret:\n  ignored_paths: ['**/README.md']\n")
                .expect("parses")
                .secret
                .ignored_paths,
            vec!["**/README.md"]
        );
        assert_eq!(
            parse("version: 1\npaths-ignore:\n  - '**/*.env'\n")
                .expect("parses")
                .secret
                .ignored_paths,
            vec!["**/*.env"]
        );
    }

    /// GIVEN the dashed spelling of a key, or the root-level
    /// `ignore_known_secrets`
    /// WHEN the config is loaded
    /// THEN both are honoured.
    #[test]
    fn dashed_and_root_level_spellings_are_honoured() {
        assert!(
            parse("version: 2\nsecret:\n  ignore-known-secrets: true\n")
                .expect("parses")
                .secret
                .ignore_known_secrets
        );
        assert!(
            parse("version: 2\nignore_known_secrets: true\n")
                .expect("parses")
                .secret
                .ignore_known_secrets
        );
        assert!(
            !parse(
                "version: 2\nignore_known_secrets: true\nsecret:\n  ignore_known_secrets: false\n"
            )
            .expect("parses")
            .secret
            .ignore_known_secrets
        );
    }

    /// GIVEN a v1 config, including a versionless one
    /// WHEN it is loaded
    /// THEN it is converted, not rejected: a versionless `.gitguardian.yaml` IS v1
    /// as far as Python is concerned.
    #[test]
    fn legacy_v1_config_is_converted() {
        let config = parse(
            "matches-ignore:\n  - deadbeef\n  - name: named one\n    match: cafebabe\n\
             banlisted-detectors:\n  - AWS Keys\npaths-ignore:\n  - '**/README.md'\n\
             show_secrets: true\nexit_zero: true\n",
        )
        .expect("v1 converts");
        assert_eq!(config.secret.ignored_matches, vec!["deadbeef", "cafebabe"]);
        assert!(config.secret.ignored_detectors.contains("AWS Keys"));
        assert!(config.exit_zero);
        assert!(!config.secret.ignore_known_secrets);

        let config = parse("matches-ignore:\n  - deadbeef\n").expect("converts");
        assert_eq!(config.secret.ignored_matches, vec!["deadbeef"]);
    }

    /// GIVEN a v1 `api_url`
    /// WHEN the config is loaded
    /// THEN it becomes the dashboard `instance`, unless one is set explicitly.
    #[test]
    fn v1_api_url_becomes_the_instance() {
        let config = parse("api-url: https://onprem.example.com/exposed\n").expect("converts");
        assert_eq!(
            config.instance.as_deref(),
            Some("https://onprem.example.com")
        );
        let config = parse(
            "api-url: https://onprem.example.com/exposed\ninstance: https://other.example.com\n",
        )
        .expect("converts");
        assert_eq!(
            config.instance.as_deref(),
            Some("https://other.example.com")
        );
    }

    /// GIVEN v1 keys that only produce a deprecation message
    /// WHEN the config is loaded
    /// THEN they change nothing and do not fail.
    #[test]
    fn v1_deprecated_keys_are_ignored_without_failing() {
        let config =
            parse("all_policies: true\nignore_default_excludes: true\n").expect("converts");
        assert!(config.secret.ignored_matches.is_empty());
    }

    /// GIVEN a config version this binary does not know
    /// WHEN it is loaded
    /// THEN it is fatal rather than fail-open, matching Python's UnexpectedError.
    #[test]
    fn unknown_config_version_is_an_error_in_both_implementations() {
        let Err(Error::Fatal(msg)) = parse("version: 3\n") else {
            panic!("an unknown version must be fatal, not fail-open");
        };
        assert!(
            msg.contains("Don't know how to load config version 3"),
            "{msg}"
        );
    }

    /// GIVEN a malformed config, or one whose ignored match has no `match` key
    /// WHEN it is loaded
    /// THEN it is fatal, as it is in Python.
    #[test]
    fn a_malformed_config_is_fatal() {
        for yaml in [
            "version: 2\nsecret:\n  - [unclosed\n",
            "- just\n- a\n- list\n",
            "version: 2\nsecret:\n  ignored_matches:\n  - name: no match key\n",
            "version: 2\nsecret:\n  ignored_detectors: nope\n",
        ] {
            assert!(
                matches!(parse(yaml), Err(Error::Fatal(_))),
                "{yaml:?} must be fatal"
            );
        }
    }

    /// GIVEN `insecure` (or its v1 spelling) and `source_uuid`
    /// WHEN the config is loaded
    /// THEN `insecure` is honoured and `source_uuid` is ignored: this hook never
    /// creates incidents.
    #[test]
    fn insecure_is_honoured_and_source_uuid_is_ignored() {
        for yaml in [
            "version: 2\ninsecure: true\n",
            "version: 2\nallow_self_signed: true\n",
            "allow-self-signed: true\n",
        ] {
            assert!(parse(yaml).expect("parses").insecure, "{yaml:?}");
        }
        parse("version: 2\nsecret:\n  source_uuid: 8b7e1f1a-0000-4000-8000-000000000000\n")
            .expect("source_uuid is ignored, not declined");
    }

    /// GIVEN a global and a local config
    /// WHEN they are merged
    /// THEN ignore lists accumulate while scalars take the local value, including
    /// across a v1/v2 mix.
    #[test]
    fn merge_appends_lists_and_overwrites_scalars() {
        let of = |yaml: &str| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join(".gitguardian.yaml");
            std::fs::write(&path, yaml).expect("write");
            load_config_file(&path).expect("parses")
        };
        let mut merged = of(
            "version: 2\ninstance: https://global.example.com\nsecret:\n  \
                            ignored_matches:\n  - match: aaa\n  ignore_known_secrets: true\n",
        );
        merged.merge(of(
            "version: 2\ninstance: https://local.example.com\nsecret:\n  \
                         ignored_matches:\n  - match: bbb\n  all_secrets: true\n  \
                         ignore_known_secrets: false\n",
        ));
        let config = merged.resolve().expect("resolves");
        assert_eq!(
            config.instance.as_deref(),
            Some("https://local.example.com")
        );
        assert_eq!(config.secret.ignored_matches, vec!["aaa", "bbb"]);
        assert!(config.secret.all_secrets);
        // The local file wins even when it sets the default value.
        assert!(!config.secret.ignore_known_secrets);

        let mut merged = of("matches-ignore:\n  - name: fp\n    match: aaa\n");
        merged.merge(of(
            "version: 2\nsecret:\n  ignored_matches:\n  - match: bbb\n",
        ));
        assert_eq!(
            merged.resolve().expect("resolves").secret.ignored_matches,
            vec!["aaa", "bbb"]
        );
    }

    /// GIVEN an empty config file
    /// WHEN it is loaded
    /// THEN it is valid and yields defaults.
    #[test]
    fn empty_config_file_is_valid() {
        let config = parse("").expect("empty file is valid");
        assert!(config.secret.ignored_matches.is_empty());
        assert!(parse("version: 2\n").is_ok());
    }
}
