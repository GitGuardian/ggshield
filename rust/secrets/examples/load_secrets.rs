use ggshield_secrets::{Provider, SecretStore};
use secrecy::ExposeSecret;

fn main() -> anyhow::Result<()> {
    let store = SecretStore::builder(Provider::Vault).build()?;

    // Vault paths are <mount>/<secret path>.
    let secrets = store.get_secrets("secret/myapp")?;
    for (key, value) in secrets {
        println!("loaded {key}");
        unsafe { std::env::set_var(key, value.expose_secret()) };
    }

    // Your app code can now read the loaded values from the environment.
    if let Ok(value) = std::env::var("STRIPE_API_KEY") {
        println!("STRIPE_API_KEY loaded ({} bytes)", value.len());
    }

    Ok(())
}
