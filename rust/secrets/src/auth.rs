use std::path::PathBuf;

use anyhow::{Result, bail};
use secrecy::{ExposeSecret, SecretString};

use crate::definition::Auth;

pub(crate) fn apply_auth(
    request: ureq::http::request::Builder,
    auth: &Auth,
) -> Result<ureq::http::request::Builder> {
    match auth {
        Auth::Token {
            token_env,
            token_file_env,
            token_file,
            header,
        } => {
            let token = resolve_token(token_env, *token_file_env, *token_file)?;
            Ok(request.header(*header, token.expose_secret()))
        }
    }
}

pub(crate) fn resolve_token(
    token_env: &str,
    token_file_env: Option<&str>,
    token_file: Option<&str>,
) -> Result<SecretString> {
    if let Ok(value) = std::env::var(token_env)
        && !value.is_empty()
    {
        return Ok(SecretString::from(value));
    }
    if let Some(path) = token_file_path(token_file_env, token_file) {
        match std::fs::read_to_string(expand_tilde(&path)) {
            Ok(contents) if !contents.trim().is_empty() => {
                return Ok(SecretString::from(contents.trim().to_string()));
            }
            // Other read failures must surface, or the user hunts for a token that exists.
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!("reading token file {path}")));
            }
        }
    }

    let file_hint = token_file_path(token_file_env, token_file)
        .map(|file| format!(" or {file}"))
        .unwrap_or_default();
    bail!("no token found (set ${token_env}{file_hint})")
}

pub(crate) fn token_file_path(
    token_file_env: Option<&str>,
    token_file: Option<&str>,
) -> Option<String> {
    if let Some(env_name) = token_file_env
        && let Ok(path) = std::env::var(env_name)
        && !path.is_empty()
    {
        return Some(path);
    }
    token_file.map(str::to_string)
}

pub(crate) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(path)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_token_falls_back_to_file() {
        let path = std::env::temp_dir().join("gg-vault-token-test");
        std::fs::write(&path, "  s.abc123\n").unwrap();
        let token = resolve_token(
            "GG_DEFINITELY_UNSET_TOKEN_ENV",
            None,
            Some(path.to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(token.expose_secret(), "s.abc123");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_token_treats_a_missing_file_as_no_token() {
        let error = resolve_token(
            "GG_DEFINITELY_UNSET_TOKEN_ENV",
            None,
            Some("/definitely/missing/gg-token"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("no token found"));
    }

    #[test]
    fn resolve_token_surfaces_unreadable_token_files() {
        // A directory is unreadable-as-a-file without being NotFound.
        let dir = std::env::temp_dir().join("gg-vault-token-dir-test");
        std::fs::create_dir_all(&dir).unwrap();
        let error = resolve_token(
            "GG_DEFINITELY_UNSET_TOKEN_ENV",
            None,
            Some(dir.to_str().unwrap()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("reading token file"));
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn token_file_path_prefers_env_then_default() {
        assert_eq!(
            token_file_path(Some("GG_TEST_VAULT_TOKEN_PATH"), Some("~/.vault-token")).as_deref(),
            Some("~/.vault-token")
        );
        // SAFETY: uniquely-named var, removed below; no other test reads it.
        unsafe { std::env::set_var("GG_TEST_VAULT_TOKEN_PATH", "/custom/token") };
        assert_eq!(
            token_file_path(Some("GG_TEST_VAULT_TOKEN_PATH"), Some("~/.vault-token")).as_deref(),
            Some("/custom/token")
        );
        unsafe { std::env::remove_var("GG_TEST_VAULT_TOKEN_PATH") };
    }

    #[test]
    fn expand_tilde_resolves_home_and_passes_absolute_paths_through() {
        if let Some(home) = std::env::home_dir() {
            assert_eq!(expand_tilde("~/.vault-token"), home.join(".vault-token"));
        }
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
    }
}
