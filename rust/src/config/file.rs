//! Parse configuration options in gitguardian YAML config files.
//! This reads both project as well as user-scoped configuration files.
use std::env::current_dir;
use std::path::PathBuf;

use gg_fs::locations::{Dir, Locations, project_root};
use gg_fs::read_to_string;
use serde_yaml_ng::{Value, from_str};

use crate::error::Error;
use crate::user_config::ConfigError;

const FILE_NAMES: [&str; 3] = [".gitguardian", ".gitguardian.yml", ".gitguardian.yaml"];

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigFile {
    path: PathBuf,
    content: Value,
}

impl ConfigFile {
    pub fn local() -> Result<Option<Self>, Error> {
        let Ok(directory) = current_dir() else {
            return Ok(None);
        };
        let root = project_root(&directory).unwrap_or(directory);
        let found = FILE_NAMES
            .iter()
            .map(|name| root.join(name))
            .find(|path| path.is_file());
        match found {
            Some(path) => Self::read(path).map(Some),
            None => Ok(None),
        }
    }

    pub fn global() -> Result<Option<Self>, Error> {
        let Ok(home) = Locations::current().dir(Dir::Home) else {
            return Ok(None);
        };
        let found = FILE_NAMES
            .iter()
            .map(|name| home.join(name))
            .find(|path| path.is_file());
        match found {
            Some(path) => Self::read(path).map(Some),
            None => Ok(None),
        }
    }

    pub fn read(path: PathBuf) -> Result<Self, Error> {
        let text = read_to_string(&path)?;
        match from_str(&text) {
            Ok(content) => Ok(Self { path, content }),
            Err(source) => Err(ConfigError::Parse { path, source }.into()),
        }
    }

    pub fn text(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            Value::String(text) => Some(text.clone()),
            Value::Bool(flag) => Some(flag.to_string()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        }
    }

    pub fn flag(&self, key: &str) -> Option<bool> {
        self.get(key)?.as_bool()
    }

    pub fn location(&self, key: &str) -> String {
        format!("{key} in {}", self.path.display())
    }

    fn get(&self, key: &str) -> Option<&Value> {
        key.split('.').try_fold(&self.content, |value, name| {
            value.get(name).or_else(|| {
                value.as_mapping()?.iter().find_map(|(candidate, found)| {
                    (candidate.as_str()?.replace('-', "_") == name).then_some(found)
                })
            })
        })
    }
}
