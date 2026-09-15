/// A provider definition: what a remote secret manager is called, where it
/// lives, how to authenticate against it and which calls it answers.
///
/// Static data rather than a parsed document. These ship with the binary and
/// nothing supplies one at runtime, so a malformed provider is a compile error
/// instead of a panic in a build script.
#[derive(Debug)]
pub struct ProviderDef {
    pub name: &'static str,
    pub description: &'static str,
    pub base_url: &'static str,
    pub auth: Auth,
    pub endpoints: &'static [(&'static str, Endpoint)],
}

impl ProviderDef {
    /// The named endpoint, or `None` when this provider has no such call.
    ///
    /// A linear scan over the handful of endpoints a provider declares, which
    /// is what lets the table be a `const`.
    pub fn endpoint(&self, name: &str) -> Option<&Endpoint> {
        self.endpoints
            .iter()
            .find(|(endpoint_name, _)| *endpoint_name == name)
            .map(|(_, endpoint)| endpoint)
    }
}

/// How to authenticate against a provider.
#[derive(Debug)]
pub enum Auth {
    /// Send a token in a header. The token is read from the `token_env`
    /// environment variable if set, otherwise from a token file whose path is
    /// `token_file_env`'s value (if set) or `token_file`.
    Token {
        token_env: &'static str,
        token_file_env: Option<&'static str>,
        token_file: Option<&'static str>,
        header: &'static str,
        scheme: Option<&'static str>,
    },
}

/// The HTTP method used to call an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Delete,
    Get,
    Post,
    Put,
}

/// A single named API call used to fetch secrets from the provider.
#[derive(Debug)]
pub struct Endpoint {
    pub method: Method,
    pub path: &'static str,
    pub query: &'static [(&'static str, &'static str)],
    /// Dot-path to the secret in the JSON response. The value there is either a
    /// map of field -> value, or a scalar (exposed as the `value` field).
    /// Dots are always separators: keys that themselves contain a `.` cannot
    /// be addressed.
    pub secret: Option<&'static str>,
}
