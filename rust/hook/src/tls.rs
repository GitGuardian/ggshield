//! Custom `ureq` agent for ggshield. It extends `ureq`'s default config as follows:
//! - trusts OS trust store to handle internal CAs
//! - trusts mozilla root certificates as fallback for edge cases without a system CA bundle
//! - respects `SSL_CERT_FILE` and `SSL_CERT_DIR` overrides on Linux
//! - respects `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` for backwards compatibility
use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use ggshield_config::config::Config;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_platform_verifier::Verifier;
use ureq::Agent;
use ureq::tls::TlsConfig;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    TcpConnector, Transport, TransportAdapter,
};

/// Creates a [ureq::Agent] for a ggshield config
pub fn agent(config: &Config) -> Result<Agent, String> {
    config
        .agent
        .get_or_init(|| build(config.user.insecure, config.ca_bundle.as_deref()))
        .clone()
}

fn build(insecure: bool, ca_bundle: Option<&str>) -> Result<Agent, String> {
    if insecure && ca_bundle.is_none() {
        let tls = TlsConfig::builder().disable_verification(true).build();
        return Ok(ureq::Agent::new_with_config(
            ureq::Agent::config_builder().tls_config(tls).build(),
        ));
    }
    let crypto_provider = Arc::new(default_provider());
    let verifier = match ca_bundle {
        Some(path) => Verifier::new_with_extra_roots(
            load_ca_bundle(Path::new(path))?,
            crypto_provider.clone(),
        ),
        None => Verifier::new(crypto_provider.clone()).or_else(|e| {
            eprintln!(
                "Warning: could not load the system trust store ({e}), falling back to \
                 Mozilla's root certificates."
            );
            Verifier::new_with_extra_roots(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec(),
                crypto_provider.clone(),
            )
        }),
    }
    .map_err(|e| e.to_string())?;
    agent_verifying(verifier, crypto_provider).map_err(|e| e.to_string())
}

/// Loads the PEM certificates from a CA bundle file or directory
fn load_ca_bundle(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let files = if path.is_dir() {
        std::fs::read_dir(path)
            .map_err(|e| {
                format!(
                    "Could not read the TLS CA certificate directory {}: {e}",
                    path.display()
                )
            })?
            .flatten()
            .map(|entry| entry.path())
            .filter(|file| file.is_file())
            .collect()
    } else if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        return Err(format!(
            "Could not find a suitable TLS CA certificate bundle, invalid path: {}",
            path.display()
        ));
    };

    let mut certs = Vec::new();
    for file in &files {
        let blocks = match CertificateDer::pem_file_iter(file) {
            Ok(blocks) => blocks,
            Err(e) => {
                eprintln!(
                    "Warning: skipping the TLS CA certificate file {}: {e}",
                    file.display()
                );
                continue;
            }
        };
        for block in blocks {
            match block {
                Ok(cert) if RootCertStore::empty().add(cert.clone()).is_ok() => certs.push(cert),
                Ok(_) => eprintln!(
                    "Warning: skipping an invalid certificate in {}",
                    file.display()
                ),
                Err(e) => eprintln!(
                    "Warning: skipping an unreadable certificate in {}: {e}",
                    file.display()
                ),
            }
        }
    }
    if certs.is_empty() {
        return Err(format!(
            "No certificate found in the TLS CA certificate bundle: {}",
            path.display()
        ));
    }
    Ok(certs)
}

/// Creates a [ureq::Agent] that verifies TLS with `verifier`
fn agent_verifying(
    verifier: Verifier,
    provider: Arc<CryptoProvider>,
) -> Result<ureq::Agent, rustls::Error> {
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let connector =
        ().chain(ConnectProxyConnector::default())
            .chain(TcpConnector::default())
            .chain(TlsConnector {
                client_config: Arc::new(client_config),
            });
    Ok(ureq::Agent::with_parts(
        ureq::config::Config::default(),
        connector,
        DefaultResolver::default(),
    ))
}

struct TlsConnector {
    client_config: Arc<ClientConfig>,
}

impl<In: Transport> Connector<In> for TlsConnector {
    type Out = Either<In, TlsTransport>;

    /// Wraps the chained transport in TLS for `https` URLs
    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }

        let host = details.uri.host().ok_or(ureq::Error::Tls(
            "no host to verify the certificate against",
        ))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(host)
            .map_err(|_| ureq::Error::Tls("invalid host name for TLS"))?
            .to_owned();

        let mut conn = ClientConnection::new(Arc::clone(&self.client_config), name)?;
        let mut sock = TransportAdapter::new(transport.boxed());
        sock.set_timeout(details.timeout);
        conn.complete_io(&mut sock)?;

        Ok(Some(Either::B(TlsTransport {
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: StreamOwned { conn, sock },
        })))
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish()
    }
}

struct TlsTransport {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl Transport for TlsTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

impl fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsTransport").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, date_time_ymd,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    fn validity(params: &mut CertificateParams) {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        let year = 1970 + (secs / 31_556_952) as i32;
        params.not_before = date_time_ymd(year - 1, 1, 1);
        params.not_after = date_time_ymd(year + 1, 1, 1);
    }

    fn https_server() -> (String, CertificateDer<'static>, String) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        validity(&mut ca_params);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().expect("ca key"))
            .expect("ca");

        let mut leaf_params =
            CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("leaf params");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut leaf_params);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = leaf_params.signed_by(&leaf_key, &ca).expect("leaf");

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config");
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("https://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&server_config)) else {
                    continue;
                };
                let mut stream = rustls::StreamOwned::new(conn, tcp);
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                let mut complete = false;
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    if line == "\r\n" {
                        complete = true;
                        break;
                    }
                    line.clear();
                }
                if complete {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = stream.flush();
                }
            }
        });
        (url, ca.der().clone(), ca.pem())
    }

    fn get(agent: &ureq::Agent, url: &str) -> Result<String, ureq::Error> {
        agent.get(url).call()?.body_mut().read_to_string()
    }

    /// GIVEN a server certificate issued by a root neither the OS nor Mozilla trusts
    /// WHEN the hook calls the server
    /// THEN the handshake fails with UnknownIssuer
    #[test]
    fn a_certificate_from_an_unknown_root_is_rejected() {
        let (url, _, _) = https_server();
        let agent = build(false, None).expect("agent");

        let error = get(&agent, &url).expect_err("unknown issuer must be rejected");

        assert!(
            error.to_string().contains("UnknownIssuer"),
            "unexpected error: {error}"
        );
    }

    /// GIVEN `insecure` in the config
    /// WHEN the hook calls a server with an untrusted certificate
    /// THEN the request succeeds
    #[test]
    fn insecure_accepts_any_certificate() {
        let (url, _, _) = https_server();
        let agent = build(true, None).expect("agent");

        assert_eq!(get(&agent, &url).expect("request"), "ok");
    }

    /// GIVEN a CA bundle file holding the server's root
    /// WHEN the hook uses it
    /// THEN the request succeeds
    #[test]
    fn a_ca_bundle_file_is_trusted() {
        let (url, _, ca_pem) = https_server();
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(&bundle, ca_pem).expect("write bundle");

        let agent = build(false, Some(bundle.to_str().expect("utf-8 path"))).expect("agent");

        assert_eq!(get(&agent, &url).expect("request"), "ok");
    }

    /// GIVEN a CA directory holding the server's root and a non-certificate file
    /// WHEN the hook uses it
    /// THEN the request succeeds
    #[test]
    fn a_ca_bundle_directory_is_trusted() {
        let (url, _, ca_pem) = https_server();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("corporate.pem"), ca_pem).expect("write cert");
        std::fs::write(dir.path().join("README"), "not a certificate").expect("write readme");

        let agent = build(false, Some(dir.path().to_str().expect("utf-8 path"))).expect("agent");

        assert_eq!(get(&agent, &url).expect("request"), "ok");
    }

    /// GIVEN a CA bundle path that does not exist
    /// WHEN the agent is built
    /// THEN it fails and names the path
    #[test]
    fn a_missing_ca_bundle_is_an_error() {
        let error = build(false, Some("/nonexistent/bundle.pem")).expect_err("missing bundle");

        assert!(
            error.contains("/nonexistent/bundle.pem"),
            "unexpected error: {error}"
        );
    }

    /// GIVEN a CA bundle file with no certificate
    /// WHEN the agent is built
    /// THEN it fails and names the path
    #[test]
    fn a_ca_bundle_without_certificates_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("empty.pem");
        std::fs::write(&bundle, "no certificate here").expect("write bundle");
        let path = bundle.to_str().expect("utf-8 path");

        let error = build(false, Some(path)).expect_err("empty bundle");

        assert!(error.contains(path), "unexpected error: {error}");
    }

    /// GIVEN `insecure` and a CA bundle that does not hold the server's root
    /// WHEN the hook calls the server
    /// THEN the certificate is still verified against the bundle, as requests does
    #[test]
    fn insecure_does_not_override_the_ca_bundle() {
        let (url, _, _) = https_server();
        let (_, _, other_ca_pem) = https_server();
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(&bundle, other_ca_pem).expect("write bundle");

        let agent = build(true, Some(bundle.to_str().expect("utf-8 path"))).expect("agent");

        let error = get(&agent, &url).expect_err("unknown issuer must be rejected");
        assert!(
            error.to_string().contains("UnknownIssuer"),
            "unexpected error: {error}"
        );
    }

    /// GIVEN `insecure` and an invalid CA bundle path
    /// WHEN the agent is built
    /// THEN it fails, as requests does
    #[test]
    fn insecure_with_a_missing_ca_bundle_is_an_error() {
        build(true, Some("/nonexistent/bundle.pem")).expect_err("missing bundle");
    }

    /// GIVEN a CA bundle holding an invalid certificate before the server's root
    /// WHEN the hook uses it
    /// THEN the invalid certificate is skipped and the request succeeds
    #[test]
    fn an_invalid_certificate_in_the_ca_bundle_is_skipped() {
        let (url, _, ca_pem) = https_server();
        let dir = tempfile::tempdir().expect("tempdir");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(
            &bundle,
            format!("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n{ca_pem}"),
        )
        .expect("write bundle");

        let agent = build(false, Some(bundle.to_str().expect("utf-8 path"))).expect("agent");

        assert_eq!(get(&agent, &url).expect("request"), "ok");
    }

    /// GIVEN a plain-HTTP URL
    /// WHEN the hook calls it
    /// THEN the connection is not wrapped in TLS
    #[test]
    fn plain_http_is_not_wrapped_in_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        std::thread::spawn(move || {
            if let Some(mut tcp) = listener.incoming().flatten().next() {
                let mut reader = BufReader::new(tcp.try_clone().expect("clone"));
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                let _ = tcp.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        let agent = build(false, None).expect("agent");

        assert_eq!(get(&agent, &url).expect("request"), "ok");
    }
}
