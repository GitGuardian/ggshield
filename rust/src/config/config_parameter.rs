//! Different subcommands of ggshield allow different
//! subsets of sources for configuration settings.
//! For example, certain subcommands do not allow
//! configuration through dotenv files.
//!
//! This module declares a container that holds
//! generic configuration settings from various sources.
//! It captures how the various sources are prioritized by
//! default and allows to inspect settings values from all sources.
#![cfg_attr(not(test), expect(dead_code))]

/// Holds the value of a configuration parameter from a configuration source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigParameterValue<T> {
    CommandArg(T),
    DotEnv(T),
    ProcessEnv(T),
    LocalConfig(T),
    GlobalConfig(T),
    DefaultValue(T),
}

impl<T> ConfigParameterValue<T> {
    pub fn get(&self) -> &T {
        match self {
            Self::CommandArg(value)
            | Self::DotEnv(value)
            | Self::ProcessEnv(value)
            | Self::LocalConfig(value)
            | Self::GlobalConfig(value)
            | Self::DefaultValue(value) => value,
        }
    }

    pub fn map<U>(self, convert: impl FnOnce(T) -> U) -> ConfigParameterValue<U> {
        match self {
            Self::CommandArg(value) => ConfigParameterValue::CommandArg(convert(value)),
            Self::DotEnv(value) => ConfigParameterValue::DotEnv(convert(value)),
            Self::ProcessEnv(value) => ConfigParameterValue::ProcessEnv(convert(value)),
            Self::LocalConfig(value) => ConfigParameterValue::LocalConfig(convert(value)),
            Self::GlobalConfig(value) => ConfigParameterValue::GlobalConfig(convert(value)),
            Self::DefaultValue(value) => ConfigParameterValue::DefaultValue(convert(value)),
        }
    }

    /// Determines the resolution order of configuration sources
    fn rank(&self) -> u8 {
        match self {
            Self::CommandArg(_) => 0,
            Self::ProcessEnv(_) => 1,
            Self::DotEnv(_) => 2,
            Self::LocalConfig(_) => 3,
            Self::GlobalConfig(_) => 4,
            Self::DefaultValue(_) => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigParameter<T> {
    values: Vec<ConfigParameterValue<T>>,
}

impl<T> ConfigParameter<T> {
    pub fn push(&mut self, value: ConfigParameterValue<T>) {
        self.values.push(value);
        self.values.sort_by_key(ConfigParameterValue::rank);
    }

    pub fn value(&self) -> Option<&T> {
        self.values.first().map(ConfigParameterValue::get)
    }

    pub fn all(&self) -> impl Iterator<Item = &T> {
        self.values.iter().map(ConfigParameterValue::get)
    }

    pub fn values(&self) -> &[ConfigParameterValue<T>] {
        &self.values
    }
}

impl<T> Default for ConfigParameter<T> {
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

impl<T> FromIterator<ConfigParameterValue<T>> for ConfigParameter<T> {
    fn from_iter<I: IntoIterator<Item = ConfigParameterValue<T>>>(values: I) -> Self {
        let mut values: Vec<_> = values.into_iter().collect();
        values.sort_by_key(ConfigParameterValue::rank);
        Self { values }
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigParameterValue::{
        CommandArg, DefaultValue, DotEnv, GlobalConfig, LocalConfig, ProcessEnv,
    };
    use super::*;

    /// GIVEN a parameter without a value from any source
    /// WHEN it is resolved
    /// THEN there is no value.
    #[test]
    fn a_parameter_without_values_resolves_to_none() {
        let parameter = ConfigParameter::<bool>::default();

        assert_eq!(parameter.value(), None);
        assert_eq!(parameter.all().count(), 0);
    }

    /// GIVEN one value from every source, given from the lowest to the highest
    /// WHEN the values are listed
    /// THEN they are in the order command argument, process environment, `.env`,
    /// local config, global config, default.
    #[test]
    fn values_are_ordered_by_the_precedence_of_their_source() {
        let parameter: ConfigParameter<&str> = [
            DefaultValue("default"),
            GlobalConfig("global"),
            LocalConfig("local"),
            DotEnv("dotenv"),
            ProcessEnv("process"),
            CommandArg("argument"),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            parameter.values(),
            [
                CommandArg("argument"),
                ProcessEnv("process"),
                DotEnv("dotenv"),
                LocalConfig("local"),
                GlobalConfig("global"),
                DefaultValue("default"),
            ]
        );
        assert_eq!(parameter.value(), Some(&"argument"));
    }

    /// GIVEN a parameter with a default
    /// WHEN no source sets a value, and then the global config sets one
    /// THEN the default is resolved first, and the global config value after.
    #[test]
    fn the_default_is_resolved_until_a_source_sets_a_value() {
        let mut parameter: ConfigParameter<u32> = [DefaultValue(60)].into_iter().collect();
        assert_eq!(parameter.value(), Some(&60));

        parameter.push(GlobalConfig(90));

        assert_eq!(parameter.value(), Some(&90));
    }

    /// GIVEN a value from the `.env` file
    /// WHEN a process environment value and then a global config value are pushed
    /// THEN the process environment value is the resolved one.
    #[test]
    fn a_pushed_value_takes_its_place_by_precedence() {
        let mut parameter = ConfigParameter::default();
        parameter.push(DotEnv(30));
        assert_eq!(parameter.value(), Some(&30));

        parameter.push(ProcessEnv(60));
        parameter.push(GlobalConfig(90));

        assert_eq!(parameter.value(), Some(&60));
        assert_eq!(
            parameter.values(),
            [ProcessEnv(60), DotEnv(30), GlobalConfig(90)]
        );
    }

    /// GIVEN a set-like parameter with values from a command argument and both
    /// config files
    /// WHEN all values are read
    /// THEN every source contributes, highest precedence first.
    #[test]
    fn all_yields_the_values_of_every_source() {
        let parameter: ConfigParameter<Vec<&str>> = [
            GlobalConfig(vec!["vendor/**"]),
            CommandArg(vec!["*.lock", "dist/**"]),
            LocalConfig(vec!["tests/**"]),
        ]
        .into_iter()
        .collect();

        let merged: Vec<&str> = parameter.all().flatten().copied().collect();

        assert_eq!(merged, ["*.lock", "dist/**", "tests/**", "vendor/**"]);
    }

    /// GIVEN two values from the same source
    /// WHEN the parameter is resolved
    /// THEN the one given first wins.
    #[test]
    fn the_first_of_two_values_from_one_source_wins() {
        let mut parameter = ConfigParameter::default();
        parameter.push(ProcessEnv("first"));
        parameter.push(ProcessEnv("second"));

        assert_eq!(parameter.value(), Some(&"first"));
    }
}
