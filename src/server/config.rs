use std::{
    fmt,
    io::{self, BufReader, Cursor, Read},
    iter,
};

use rustls_pemfile::Item;
use tokio_rustls::rustls::{
    server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth},
    Certificate, Error as TlsError, PrivateKey, RootCertStore, ServerConfig,
};

/// Represents errors that can occur building the TlsConfig
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("{0}")]
    Io(#[from] io::Error),
    /// An Error parsing the Certificate
    #[error("certificate parse error")]
    CertParseError,
    /// An error from an empty key
    #[error("key contains no private key")]
    EmptyKey,
    /// An error from an invalid key
    #[error("key contains an invalid key: {0}")]
    InvalidKey(#[from] TlsError),
}

/// Tls client authentication configuration.
enum TlsClientAuth {
    /// No client auth.
    Off,
    /// Allow any anonymous or authenticated client.
    Optional(Box<dyn Read + Send + Sync>),
    /// Allow any authenticated client.
    Required(Box<dyn Read + Send + Sync>),
}

/// Builder to set the configuration for the Tls server.
pub struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
    client_auth: TlsClientAuth,
    ocsp_resp: Vec<u8>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfigBuilder").finish()
    }
}

impl Default for TlsConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsConfigBuilder {
    /// Create a new TlsConfigBuilder
    pub fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
            client_auth: TlsClientAuth::Off,
            ocsp_resp: Vec::new(),
            alpn_protocols: Vec::new(),
        }
    }

    /// Sets the TLS certificate and key via bytes slice
    pub fn cert_key(mut self, cert: &[u8], key: &[u8]) -> Self {
        self.cert = Box::new(Cursor::new(Vec::from(cert)));
        self.key = Box::new(Cursor::new(Vec::from(key)));
        self
    }

    /// Sets the trust anchor for optional Tls client authentication via bytes slice.
    ///
    /// Anonymous and authenticated clients will be accepted. If no trust anchor is provided by any
    /// of the `client_auth_` methods, then client authentication is disabled by default.
    pub fn client_auth_optional(mut self, trust_anchor: &[u8]) -> Self {
        let cursor = Box::new(Cursor::new(Vec::from(trust_anchor)));
        self.client_auth = TlsClientAuth::Optional(cursor);
        self
    }

    /// Sets the trust anchor for required Tls client authentication via bytes slice.
    ///
    /// Only authenticated clients will be accepted. If no trust anchor is provided by any of the
    /// `client_auth_` methods, then client authentication is disabled by default.
    pub fn client_auth_required(mut self, trust_anchor: &[u8]) -> Self {
        let cursor = Box::new(Cursor::new(Vec::from(trust_anchor)));
        self.client_auth = TlsClientAuth::Required(cursor);
        self
    }

    /// Sets the DER-encoded OCSP response
    pub fn ocsp_resp(mut self, ocsp_resp: &[u8]) -> Self {
        self.ocsp_resp = Vec::from(ocsp_resp);
        self
    }

    /// Sets the APLN protocols
    /// Protocol names we support, most preferred first.
    /// If empty we don't do ALPN at all.
    pub fn alpn_protocols<T>(mut self, alpn_protocols: T) -> Self
    where
        T: IntoIterator,
        T::Item: Into<Vec<u8>>,
    {
        self.alpn_protocols = Vec::from_iter(alpn_protocols.into_iter().map(|v| v.into()));
        self
    }

    pub fn build(self) -> Result<ServerConfig, TlsConfigError> {
        let mut cert_rd = BufReader::new(self.cert);
        let cert = read_certs(&mut cert_rd)?;

        let mut key_rd = BufReader::new(self.key);
        let key = read_key(&mut key_rd)?;

        let client_auth = match self.client_auth {
            TlsClientAuth::Off => NoClientAuth::new(),
            TlsClientAuth::Optional(trust_anchor) => {
                AllowAnyAnonymousOrAuthenticatedClient::new(read_trust_anchor(trust_anchor)?)
            }
            TlsClientAuth::Required(trust_anchor) => {
                AllowAnyAuthenticatedClient::new(read_trust_anchor(trust_anchor)?)
            }
        };

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_auth)
            .with_single_cert_with_ocsp_and_sct(cert, key, self.ocsp_resp, Vec::new())
            .map_err(TlsConfigError::InvalidKey)?;
        config.alpn_protocols = self.alpn_protocols;

        Ok(config)
    }
}

#[inline]
fn read_certs(rd: &mut dyn io::BufRead) -> Result<Vec<Certificate>, TlsConfigError> {
    let cert = rustls_pemfile::certs(rd)
        .map_err(|_e| TlsConfigError::CertParseError)?
        .into_iter()
        .map(Certificate)
        .collect();

    Ok(cert)
}

#[inline]
fn read_key(rd: &mut dyn io::BufRead) -> Result<PrivateKey, TlsConfigError> {
    for item in iter::from_fn(|| rustls_pemfile::read_one(rd).transpose()) {
        let key = match item.map_err(TlsConfigError::Io)? {
            Item::RSAKey(key) => key,
            Item::PKCS8Key(key) => key,
            Item::ECKey(key) => key,
            _ => continue,
        };

        return Ok(PrivateKey(key));
    }

    Err(TlsConfigError::EmptyKey)
}

#[inline]
fn read_trust_anchor(
    trust_anchor: Box<dyn Read + Send + Sync>,
) -> Result<RootCertStore, TlsConfigError> {
    let trust_anchors = {
        let mut reader = BufReader::new(trust_anchor);
        rustls_pemfile::certs(&mut reader).map_err(TlsConfigError::Io)?
    };

    let mut store = RootCertStore::empty();
    let (added, _skipped) = store.add_parsable_certificates(&trust_anchors);
    if added == 0 {
        return Err(TlsConfigError::CertParseError);
    }

    Ok(store)
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader, path::PathBuf};

    use super::*;

    fn target_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn read_certificate() {
        let file = File::open(target_dir().join("tests/cert.pem")).unwrap();
        let mut rd = BufReader::new(file);
        read_certs(&mut rd).unwrap();
    }

    #[test]
    fn read_ec_key() {
        let file = File::open(target_dir().join("tests/key.pem")).unwrap();
        let mut rd = BufReader::new(file);
        read_key(&mut rd).unwrap();
    }
}
