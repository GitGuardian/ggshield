//! The global configuration of ggshield.
//! Subcommands should define their own configurations
//! to define command-specific configuration settings
//! using the [crate::config::Setting] builder to build
//! from the collected configuration [crate::config::Sources].
use std::io::Error as IoError;
use std::path::PathBuf;

use clap::CommandFactory;
use clap::error::ErrorKind;
use gg_url::{ApiUrl, DashboardUrl};
use log::LevelFilter;
use serde_yaml_ng::Error as YamlError;

use crate::cli::GGShield;
use crate::config::config_parameter::ConfigParameter;
pub use crate::config::config_parameter::ConfigParameterValue;
use crate::config::config_parameter::ConfigParameterValue::{
    CommandArg, DefaultValue, DotEnv, ProcessEnv,
};
pub use crate::config::sources::{Setting, Sources};
use crate::error::Error;

mod config_parameter;
mod env;
mod file;
mod sources;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not locate the ggshield config directory")]
    DirectoryNotFound,
    #[error("{}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: IoError,
    },
    #[error("{}", .path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: YamlError,
    },
    #[error("Don't know how to load config version {0}")]
    UnsupportedVersion(i64),
    #[error("{}: line {line}, column {column}: {reason}", .path.display())]
    DotEnvSyntax {
        path: PathBuf,
        line: usize,
        column: usize,
        reason: String,
    },
}

/// The configuration of ggshield, consolidated from various sources.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(dead_code)]
pub struct Config {
    pub config_path: ConfigParameter<PathBuf>,
    pub instance: ConfigParameter<DashboardUrl>,
    pub verbosity: ConfigParameter<LevelFilter>,
    pub insecure: ConfigParameter<bool>,
    pub check_for_updates: ConfigParameter<bool>,
}

impl TryFrom<&Sources> for Config {
    type Error = Error;

    fn try_from(sources: &Sources) -> Result<Self, Self::Error> {
        let config_path = sources.setting(Setting::new().option("config_path"))?;

        let mut instance = sources.setting(
            Setting::new()
                .option("instance")
                .variable("GITGUARDIAN_INSTANCE")
                .key("instance")
                .default_value(DashboardUrl::default()),
        )?;
        let api_url = sources.setting::<ApiUrl>(Setting::new().variable("GITGUARDIAN_API_URL"))?;
        let instance_in_environment = instance
            .values()
            .iter()
            .any(|value| matches!(value, ProcessEnv(_) | DotEnv(_)));
        if !instance_in_environment {
            for value in api_url.values() {
                instance.push(value.clone().map(DashboardUrl::from));
            }
        }

        let verbose = sources.setting::<u8>(Setting::new().option("verbose"))?;
        let debug = sources.flag(Setting::new().option("debug"));
        let mut verbosity = ConfigParameter::default();
        verbosity.push(DefaultValue(LevelFilter::Info));
        match (debug.value().copied(), verbose.value().copied()) {
            (Some(true), _) | (_, Some(2..)) => verbosity.push(CommandArg(LevelFilter::Trace)),
            (_, Some(1)) => verbosity.push(CommandArg(LevelFilter::Debug)),
            _ => {}
        }

        let mut insecure = sources.flag(
            Setting::new()
                .option("insecure")
                .key("insecure")
                .default_value(false),
        );
        let allow_self_signed = sources.flag(Setting::new().option("allow_self_signed"));
        if allow_self_signed.value() == Some(&true) {
            insecure.push(CommandArg(true));
        }

        let check = sources.flag(Setting::new().option("check_for_updates"));
        let no_check = sources.flag(Setting::new().option("no_check_for_updates"));
        let mut check_for_updates = ConfigParameter::default();
        check_for_updates.push(DefaultValue(true));
        match (check.value().copied(), no_check.value().copied()) {
            (Some(true), Some(true)) => {
                let conflict = GGShield::command().error(
                    ErrorKind::ArgumentConflict,
                    "the argument '--check-for-updates' cannot be used with '--no-check-for-updates'",
                );
                return Err(conflict.into());
            }
            (Some(true), _) => check_for_updates.push(CommandArg(true)),
            (_, Some(true)) => check_for_updates.push(CommandArg(false)),
            _ => {}
        }

        Ok(Config {
            config_path,
            instance,
            verbosity,
            insecure,
            check_for_updates,
        })
    }
}
