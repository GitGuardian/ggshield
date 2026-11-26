//! Collects the different config sources
//! - CLI arguments
//! - Process environment variables
//! - Environment variables loaded from dotenv
//! - Project-scoped gitguardian YAML config file
//! - User-scoped gitguardian YAML config file
//! - Default configuration settings
//!
//! The module exposes a builder that commands and subcommands should
//! use to build their configurations.
#![expect(dead_code)]

use std::error::Error as StdError;
use std::path::PathBuf;
use std::str::FromStr;

use clap::ArgMatches;
use clap::parser::ValueSource;

use crate::config::config_parameter::ConfigParameter;
use crate::config::config_parameter::ConfigParameterValue::{
    CommandArg, DefaultValue, DotEnv, GlobalConfig, LocalConfig, ProcessEnv,
};
use crate::config::env::Env;
use crate::config::file::ConfigFile;
use crate::error::{Cause, Error};

pub struct Setting<T> {
    option: Option<&'static str>,
    variable: Option<&'static str>,
    key: Option<&'static str>,
    default: Option<T>,
    allow_dot_env: bool,
}

impl<T> Setting<T> {
    pub fn new() -> Self {
        Self {
            option: None,
            variable: None,
            key: None,
            default: None,
            allow_dot_env: true,
        }
    }

    pub fn option(mut self, name: &'static str) -> Self {
        self.option = Some(name);
        self
    }

    pub fn variable(mut self, name: &'static str) -> Self {
        self.variable = Some(name);
        self
    }

    pub fn key(mut self, key: &'static str) -> Self {
        self.key = Some(key);
        self
    }

    pub fn default_value(mut self, value: T) -> Self {
        self.default = Some(value);
        self
    }

    pub fn without_dot_env(mut self) -> Self {
        self.allow_dot_env = false;
        self
    }
}

impl<T> Default for Setting<T> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Sources {
    args: ArgMatches,
    process: Env,
    dot_env: Option<Env>,
    local: Option<ConfigFile>,
    global: Option<ConfigFile>,
}

impl Sources {
    pub fn load(args: ArgMatches) -> Result<Self, Error> {
        let process = Env::process();
        let dot_env = Env::dot_env(&process)?;
        let (local, global) = match argument(&args, "config_path") {
            Some(path) => (None, Some(ConfigFile::read(PathBuf::from(path))?)),
            None => (ConfigFile::local()?, ConfigFile::global()?),
        };
        Ok(Self {
            args,
            process,
            dot_env,
            local,
            global,
        })
    }

    pub fn setting<T>(&self, setting: Setting<T>) -> Result<ConfigParameter<T>, Error>
    where
        T: FromStr,
        T::Err: StdError + Send + Sync + 'static,
    {
        let mut parameter = ConfigParameter::default();
        if let Some(name) = setting.option
            && let Some(text) = argument(&self.args, name)
        {
            parameter.push(CommandArg(parse(&text, format!("option {name}"))?));
        }
        if let Some(name) = setting.variable {
            if let Some(text) = self.process.get(name) {
                parameter.push(ProcessEnv(parse(text, self.process.location(name))?));
            }
            if setting.allow_dot_env
                && let Some(dot_env) = &self.dot_env
                && let Some(text) = dot_env.get(name)
            {
                parameter.push(DotEnv(parse(text, dot_env.location(name))?));
            }
        }
        if let Some(key) = setting.key {
            if let Some(file) = &self.local
                && let Some(text) = file.text(key)
            {
                parameter.push(LocalConfig(parse(&text, file.location(key))?));
            }
            if let Some(file) = &self.global
                && let Some(text) = file.text(key)
            {
                parameter.push(GlobalConfig(parse(&text, file.location(key))?));
            }
        }
        if let Some(default) = setting.default {
            parameter.push(DefaultValue(default));
        }
        Ok(parameter)
    }

    pub fn flag(&self, setting: Setting<bool>) -> ConfigParameter<bool> {
        let mut parameter = ConfigParameter::default();
        if let Some(name) = setting.option
            && let Some(text) = argument(&self.args, name)
        {
            parameter.push(CommandArg(text == "true"));
        }
        if let Some(name) = setting.variable {
            if let Some(flag) = self.process.flag(name) {
                parameter.push(ProcessEnv(flag));
            }
            if setting.allow_dot_env
                && let Some(dot_env) = &self.dot_env
                && let Some(flag) = dot_env.flag(name)
            {
                parameter.push(DotEnv(flag));
            }
        }
        if let Some(key) = setting.key {
            if let Some(file) = &self.local
                && let Some(flag) = file.flag(key)
            {
                parameter.push(LocalConfig(flag));
            }
            if let Some(file) = &self.global
                && let Some(flag) = file.flag(key)
            {
                parameter.push(GlobalConfig(flag));
            }
        }
        if let Some(default) = setting.default {
            parameter.push(DefaultValue(default));
        }
        parameter
    }
}

fn argument(args: &ArgMatches, name: &str) -> Option<String> {
    let mut level = args;
    loop {
        if level.try_contains_id(name).is_ok()
            && level.value_source(name) == Some(ValueSource::CommandLine)
        {
            let mut values = level.try_get_raw(name).ok().flatten()?;
            let value = values.next_back()?;
            return Some(value.to_string_lossy().into_owned());
        }
        level = level.subcommand()?.1;
    }
}

fn parse<T>(text: &str, location: String) -> Result<T, Error>
where
    T: FromStr,
    T::Err: StdError + Send + Sync + 'static,
{
    match text.parse() {
        Ok(value) => Ok(value),
        Err(source) => Err(Error::from(Cause::InvalidSetting(Box::new(source))).context(location)),
    }
}
