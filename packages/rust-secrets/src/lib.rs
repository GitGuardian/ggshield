//! ggshield-secrets — the secret-resolution engine and Rust SDK.
//!
//! The high-level entry point is [`SecretStore`]: build one for a [`Provider`],
//! then read secrets directly from your application code.
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
//! Providers are declared as data in `providers/<name>.yaml` and exposed as the
//! [`Provider`] enum; anything YAML can't express (request signing, multi-step
//! token exchange) is a coded `auth` strategy referenced by name. Resolved
//! secret values are returned as [`secrecy::SecretString`] so they are not
//! accidentally leaked through `Debug`, logs, or error messages — callers must
//! opt in with `expose_secret()` to read them.

mod auth;
mod definition;
pub mod dotenv;
mod error;
mod file;
mod json;
mod provider;
mod store;

pub use definition::{Auth, Endpoint, Method, ProviderDef};
pub use error::SecretError;
pub use file::trust;
pub use file::{
    DEFAULT_PROJECT_PATH, DeleteOutcome, DeletePlan, EncryptOutcome, ReadWarnings, user_scope_path,
};
pub use provider::{Provider, credential_env_vars};
pub use store::{SecretStore, SecretStoreBuilder};
