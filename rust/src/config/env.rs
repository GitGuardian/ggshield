//! Parse configuration options in runtime
//! environment variables. These variables
//! can come from process environment variables
//! or dotenv files.
use std::collections::HashMap;
use std::env::{current_dir, vars_os};
use std::io::Error as IoError;
use std::path::{PathBuf, absolute};

use dotenv::{EnvLoader, EnvSequence, Error as DotEnvError};
use gg_fs::locations::project_root;
use gg_fs::read_to_string;
use log::warn;

use crate::config::ConfigError;
use crate::error::Error;

const DONT_LOAD_ENV: &str = "GITGUARDIAN_DONT_LOAD_ENV";
const DOTENV_PATH: &str = "GITGUARDIAN_DOTENV_PATH";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    Process,
    DotEnv(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    origin: Origin,
    variables: HashMap<String, String>,
}

impl Env {
    pub fn process() -> Self {
        let variables = vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .map(|(name, value)| {
                if cfg!(windows) {
                    (name.to_uppercase(), value)
                } else {
                    (name, value)
                }
            })
            .collect();
        Self {
            origin: Origin::Process,
            variables,
        }
    }

    /// Loads the `.env` file named by `GITGUARDIAN_DOTENV_PATH`, or else the one
    /// in the current directory or at the git root. Returns `None` if there is no
    /// file or `GITGUARDIAN_DONT_LOAD_ENV` is set. Invalid lines are skipped.
    pub fn dot_env(process: &Env) -> Result<Option<Self>, Error> {
        if process.flag(DONT_LOAD_ENV) == Some(true) {
            return Ok(None);
        }
        if let Some(path) = process.get(DOTENV_PATH).filter(|path| !path.is_empty()) {
            let path = absolute(path).unwrap_or_else(|_| PathBuf::from(path));
            return Self::read_dot_env(path, process)
                .map(Some)
                .map_err(|error| error.context(process.location(DOTENV_PATH)));
        }
        let Ok(directory) = current_dir() else {
            return Ok(None);
        };
        let root = project_root(&directory);
        let found = [Some(directory), root]
            .into_iter()
            .flatten()
            .map(|directory| directory.join(".env"))
            .find(|path| path.is_file());
        match found {
            Some(path) => Self::read_dot_env(path, process).map(Some),
            None => Ok(None),
        }
    }

    fn read_dot_env(path: PathBuf, process: &Env) -> Result<Self, Error> {
        let content = read_to_string(&path)?;
        let mut lines: Vec<&str> = content.lines().collect();
        loop {
            let text = lines.join("\n");
            let loaded = EnvLoader::with_reader(text.as_bytes())
                .sequence(EnvSequence::InputOnly)
                .substitution(true)
                .substitutions(&process.variables)
                .load();
            let error = match loaded {
                Ok(variables) => {
                    return Ok(Self {
                        origin: Origin::DotEnv(path),
                        variables: variables
                            .into_iter()
                            .map(|(name, value)| {
                                if cfg!(windows) {
                                    (name.to_uppercase(), value)
                                } else {
                                    (name, value)
                                }
                            })
                            .collect(),
                    });
                }
                Err(DotEnvError::Parse(error, _)) => error,
                Err(error) => {
                    let source = IoError::other(error);
                    return Err(ConfigError::Read { path, source }.into());
                }
            };
            let line = error.line();
            let column = error.column();
            let reason = error.kind().to_string();
            match lines.get_mut(line.wrapping_sub(1)) {
                Some(skipped) if !skipped.is_empty() => {
                    warn!(
                        "{}: skipped line {line}, column {column}: {reason}",
                        path.display()
                    );
                    *skipped = "";
                }
                _ => {
                    let cause = ConfigError::DotEnvSyntax {
                        path,
                        line,
                        column,
                        reason,
                    };
                    return Err(cause.into());
                }
            }
        }
    }

    pub fn flag(&self, name: &str) -> Option<bool> {
        self.get(name)
            .map(|value| !matches!(value.to_lowercase().as_str(), "false" | "0"))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(String::as_str)
    }

    pub fn location(&self, name: &str) -> String {
        match &self.origin {
            Origin::Process => format!("{name} in the process environment"),
            Origin::DotEnv(path) => format!("{name} in {}", path.display()),
        }
    }
}
