//! Secret-resolution engine and Rust SDK; start from [`SecretStore`].
//!
//! ```no_run
//! # fn run() -> anyhow::Result<()> {
//! use ggshield_secrets::{Provider, SecretStore};
//! use secrecy::ExposeSecret;
//!
//! let store = SecretStore::builder(Provider::Vault).build()?;
//! let stripe = store.get_secret("secret/myapp", "STRIPE_KEY")?;
//! println!("{}", stripe.expose_secret());
//! # Ok(())
//! # }
//! ```
//!
//! Values come back as [`secrecy::SecretString`] so they never leak through
//! `Debug` or logs without an explicit `expose_secret()`.

mod auth;
mod definition;
pub mod dotenv;
mod error;
mod file;
mod json;
mod provider;
pub(crate) mod providers;
mod store;

pub use definition::{Auth, Endpoint, Method, ProviderDef};
pub use error::SecretError;
pub use file::trust;
pub use file::{
    DEFAULT_PROJECT_PATH, DeleteOutcome, DeletePlan, EncryptOutcome, ReadWarnings, repo_scope_path,
    system_scope_path, user_scope_path,
};
pub use provider::{Provider, credential_env_vars};
pub use store::{SecretStore, SecretStoreBuilder};
