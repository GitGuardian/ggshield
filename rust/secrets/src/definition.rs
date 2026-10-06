/// Static rather than parsed so a malformed provider is a compile error, not a runtime panic.
#[derive(Debug)]
pub struct ProviderDef {
    pub name: &'static str,
    pub description: &'static str,
    pub base_url: &'static str,
    pub auth: Auth,
    pub endpoints: &'static [(&'static str, Endpoint)],
}

impl ProviderDef {
    pub fn endpoint(&self, name: &str) -> Option<&Endpoint> {
        self.endpoints
            .iter()
            .find(|(endpoint_name, _)| *endpoint_name == name)
            .map(|(_, endpoint)| endpoint)
    }
}

#[derive(Debug)]
pub enum Auth {
    /// Token from `token_env`, else the file at `token_file_env`'s value or `token_file`.
    Token {
        token_env: &'static str,
        token_file_env: Option<&'static str>,
        token_file: Option<&'static str>,
        header: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Delete,
    Get,
    Post,
}

#[derive(Debug)]
pub struct Endpoint {
    pub method: Method,
    pub path: &'static str,
    pub query: &'static [(&'static str, &'static str)],
    /// Dot-path to the secret in the JSON response; keys containing `.` cannot be addressed.
    pub secret: Option<&'static str>,
}
