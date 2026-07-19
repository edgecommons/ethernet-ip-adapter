//! # CIP Security TLS policy + material sourcing (the adapter side of the split)
//!
//! The `enip` crate owns TLS-*the-transport* (`connect_tls`, the handshake, the error taxonomy) and
//! takes an opaque `rustls::ClientConfig`. **This module owns everything else** (DESIGN-cip-security.md
//! §3.2): the `connection.security` config surface, its validation, sourcing cert/key/CA bytes from the
//! EdgeCommons credentials vault (`gg.credentials().get_tls_bundle`) or from files, and building the
//! verified (or deliberately-unverified) `rustls::ClientConfig` — including the IP-SAN server name a
//! PLC dialed by IP needs, an optional cipher-suite constraint, and the expiry-tolerant verifier for
//! RTC-less devices. Key material lives only as long as the `ClientConfig` build and is never logged.
//!
//! `rustls` here is the same 0.23 the `enip` `tls` feature re-exports (`enip::rustls`), so the
//! `ClientConfig`/`ServerName` types unify across the seam.

use std::sync::Arc;

use serde::Deserialize;

use edgecommons::credentials::CredentialService;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore};

use crate::device::{ConnectionConfig, SecurityStatus};

/// The `connection.security` block (DESIGN-cip-security.md §3.3) — a strict typed island inside the
/// deliberately-open `connection` object. Absent ⇒ plaintext (the default).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityConfig {
    /// `plaintext` (default) or `tls`.
    #[serde(default)]
    pub mode: SecurityMode,
    /// The adapter's own identity for mutual TLS.
    #[serde(default)]
    pub client: Option<ClientIdentity>,
    /// Trust anchors for verifying the device certificate.
    #[serde(default)]
    pub ca: Option<CaSource>,
    /// `false` ⇒ accept any device certificate (a loud, event-raising commissioning/debug mode).
    #[serde(default = "d_true")]
    pub verify_peer: bool,
    /// Verification / SNI name; default = the endpoint host (an IP ⇒ IP-SAN verification).
    #[serde(default)]
    pub server_name: Option<String>,
    /// `false` ⇒ tolerate an expired/not-yet-valid device certificate (RTC-less devices).
    #[serde(default = "d_true")]
    pub check_expiration: bool,
    /// Optional cipher-suite allow-list (IANA / rustls names). Default = the rustls defaults (the
    /// GCM + TLS 1.3 suites Vol 8 ≥ 1.13 mandates).
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
}

/// `plaintext` | `tls` (DESIGN-cip-security.md §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    /// Plaintext EtherNet/IP (TCP 44818) — the default.
    #[default]
    Plaintext,
    /// EtherNet/IP over TLS (CIP Security explicit path, TCP 2221).
    Tls,
}

/// The adapter's client identity: a vault TLS bundle (`certSecret`) OR a PEM cert+key file pair.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientIdentity {
    /// A vault secret name holding a `{certPem, keyPem[, caPem]}` TLS bundle.
    #[serde(default)]
    pub cert_secret: Option<String>,
    /// A PEM certificate (chain) file path.
    #[serde(default)]
    pub cert_file: Option<String>,
    /// A PEM private-key file path.
    #[serde(default)]
    pub key_file: Option<String>,
}

/// The trust anchors: a vault secret name (PEM, possibly several roots) OR a PEM file path.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaSource {
    /// A vault secret name holding CA certificate PEM.
    #[serde(default)]
    pub secret: Option<String>,
    /// A CA PEM file path.
    #[serde(default)]
    pub file: Option<String>,
}

fn d_true() -> bool {
    true
}

/// The out-of-band material the adapter carries alongside the built `TlsOptions` for the status
/// surface (things the `enip` crate cannot know: our own cert's expiry + the verify policy).
#[derive(Debug, Clone, Default)]
pub struct TlsMeta {
    /// The adapter client certificate's `notAfter`, RFC-3339.
    pub client_cert_not_after: Option<String>,
    /// The configured `verifyPeer` policy (a no-verify session reports `peerVerified: false`).
    pub verify_peer: bool,
}

impl SecurityConfig {
    /// Parse the `security` block from a `connection` (it rides in the open `extra` map). Returns
    /// `Ok(None)` when absent.
    ///
    /// # Errors
    ///
    /// A message when the block is present but malformed (unknown key, bad type).
    pub fn from_connection(conn: &ConnectionConfig) -> std::result::Result<Option<Self>, String> {
        match conn.extra.get("security") {
            None => Ok(None),
            Some(v) => serde_json::from_value::<Self>(v.clone())
                .map(Some)
                .map_err(|e| format!("connection.security: {e}")),
        }
    }

    /// Whether TLS is requested.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.mode == SecurityMode::Tls
    }

    /// Fail-fast startup validation (DESIGN-cip-security.md §3.3): TLS is refused on a push instance,
    /// requires a client identity, and (with `verifyPeer`) a CA source.
    ///
    /// # Errors
    ///
    /// A message describing the first problem.
    pub fn validate(&self, device_id: &str, is_push: bool) -> std::result::Result<(), String> {
        if !self.is_tls() {
            return Ok(());
        }
        // TLS-explicit forces refusing plaintext I/O — no silent downgrade to the CT23-deprecated
        // "TLS session opening plaintext class-1" (DESIGN-cip-security.md §3.1).
        if is_push {
            return Err(format!(
                "device `{device_id}`: security.mode `tls` is not supported on a push (class-1 I/O) \
                 instance — implicit I/O requires DTLS, which is not available; see limitations"
            ));
        }
        // A partial file identity (only one of certFile/keyFile) is a specific, common mistake — name
        // it precisely, ahead of the generic "requires a client identity" message.
        if let Some(c) = &self.client {
            if c.cert_secret.is_none() && c.cert_file.is_some() != c.key_file.is_some() {
                return Err(format!(
                    "device `{device_id}`: security.client needs BOTH certFile and keyFile \
                     (or use certSecret)"
                ));
            }
        }
        // A CIP Security device requires a client certificate (0x5E attr 9), so an identity-less TLS
        // config is almost certainly a misconfiguration.
        let has_client = self.client.as_ref().is_some_and(|c| {
            c.cert_secret.is_some() || (c.cert_file.is_some() && c.key_file.is_some())
        });
        if !has_client {
            return Err(format!(
                "device `{device_id}`: security.mode `tls` requires a client identity \
                 (client.certSecret, or client.certFile + client.keyFile)"
            ));
        }
        // Verifying the peer needs trust anchors — either an explicit ca source, or a certSecret
        // bundle that may carry caPem (resolved at connect time).
        if self.verify_peer {
            let has_ca = self.ca.as_ref().is_some_and(|c| c.secret.is_some() || c.file.is_some());
            let bundle_may_have_ca =
                self.client.as_ref().is_some_and(|c| c.cert_secret.is_some());
            if !has_ca && !bundle_may_have_ca {
                return Err(format!(
                    "device `{device_id}`: security.mode `tls` with verifyPeer requires a CA source \
                     (ca.secret or ca.file) unless the client bundle (certSecret) carries caPem"
                ));
            }
        }
        Ok(())
    }
}

/// Read a file into a string, mapping the IO error to a config-legible message.
fn read_pem_file(path: &str, what: &str) -> std::result::Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {what} `{path}`: {e}"))
}

/// Parse a PEM blob into a DER certificate chain.
fn certs_from_pem(pem: &str, what: &str) -> std::result::Result<Vec<CertificateDer<'static>>, String> {
    let mut rd = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("parsing {what} PEM: {e}"))
}

/// Parse the first private key out of a PEM blob (PKCS#8 / RSA / SEC1).
fn key_from_pem(pem: &str) -> std::result::Result<PrivateKeyDer<'static>, String> {
    let mut rd = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| format!("parsing private key PEM: {e}"))?
        .ok_or_else(|| "no private key found in key PEM".to_string())
}

/// The endpoint host without any `:port` suffix (best-effort; leaves bracketed IPv6 alone).
fn host_of(endpoint: &str) -> String {
    if endpoint.starts_with('[') {
        // [ipv6]:port
        if let Some(end) = endpoint.find(']') {
            return endpoint[1..end].to_string();
        }
    }
    match endpoint.rsplit_once(':') {
        // Only strip a trailing group if it looks like a port (all digits) — avoids eating an IPv6.
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => endpoint.to_string(),
    }
}

/// Resolve the verification / SNI name: `serverName` if set, else the endpoint host. An IP literal
/// becomes a [`ServerName::IpAddress`] (verified against the device cert's IP SAN); anything else a
/// DNS name.
fn resolve_server_name(
    sec: &SecurityConfig,
    conn: &ConnectionConfig,
) -> std::result::Result<ServerName<'static>, String> {
    let raw = sec
        .server_name
        .clone()
        .unwrap_or_else(|| host_of(&conn.endpoint));
    if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(raw.clone()).map_err(|e| format!("invalid serverName `{raw}`: {e}"))
    }
}

/// Build the ring crypto provider, optionally constrained to `sec.cipher_suites` (matched
/// case-insensitively against rustls's suite names, e.g. `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`).
fn provider_for(sec: &SecurityConfig) -> std::result::Result<CryptoProvider, String> {
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(names) = &sec.cipher_suites {
        let wanted: Vec<String> = names.iter().map(|s| s.to_ascii_uppercase()).collect();
        provider
            .cipher_suites
            .retain(|cs| wanted.contains(&format!("{:?}", cs.suite()).to_ascii_uppercase()));
        if provider.cipher_suites.is_empty() {
            return Err(format!(
                "security.cipherSuites {names:?} matched no supported suite — rustls speaks the \
                 GCM/TLS1.3 suites (e.g. TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
                 TLS13_AES_128_GCM_SHA256), not CBC/NULL/PSK"
            ));
        }
    }
    Ok(provider)
}

/// Build the `rustls::ClientConfig` + [`TlsMeta`] from the security config, sourcing cert/key/CA
/// bytes from the vault (`creds`) or from files (DESIGN-cip-security.md §3.2/§3.3).
///
/// # Errors
///
/// A config-legible message for any sourcing/parse/verifier-build failure.
pub fn build_client_config(
    sec: &SecurityConfig,
    conn: &ConnectionConfig,
    creds: Option<&Arc<dyn CredentialService>>,
) -> std::result::Result<(enip::TlsOptions, TlsMeta), String> {
    let mut root_pems: Vec<String> = Vec::new();
    let mut client_cert_pem: Option<String> = None;
    let mut client_key_pem: Option<String> = None;

    // ---- client identity ----
    if let Some(c) = &sec.client {
        if let Some(name) = &c.cert_secret {
            let creds = creds.ok_or_else(|| {
                format!("client.certSecret `{name}` is set but no credentials vault is configured")
            })?;
            let bundle = creds
                .get_tls_bundle(name)
                .map_err(|e| format!("vault get_tls_bundle(`{name}`): {e}"))?
                .ok_or_else(|| format!("vault TLS bundle `{name}` not found"))?;
            client_cert_pem = Some(bundle.cert_pem);
            client_key_pem = Some(bundle.key_pem);
            if let Some(ca) = bundle.ca_pem {
                root_pems.push(ca);
            }
        } else if let (Some(cf), Some(kf)) = (&c.cert_file, &c.key_file) {
            client_cert_pem = Some(read_pem_file(cf, "client certificate")?);
            client_key_pem = Some(read_pem_file(kf, "client key")?);
        }
    }

    // ---- trust anchors ----
    if let Some(ca) = &sec.ca {
        if let Some(name) = &ca.secret {
            let creds = creds.ok_or_else(|| {
                format!("ca.secret `{name}` is set but no credentials vault is configured")
            })?;
            let pem = creds
                .get_string(name)
                .map_err(|e| format!("vault get_string(`{name}`): {e}"))?
                .ok_or_else(|| format!("vault CA secret `{name}` not found"))?;
            root_pems.push(pem);
        } else if let Some(f) = &ca.file {
            root_pems.push(read_pem_file(f, "CA certificate")?);
        }
    }

    let mut roots = RootCertStore::empty();
    for pem in &root_pems {
        for cert in certs_from_pem(pem, "CA")? {
            roots
                .add(cert)
                .map_err(|e| format!("adding CA certificate to the trust store: {e}"))?;
        }
    }

    let client_identity = match (client_cert_pem, client_key_pem) {
        (Some(cp), Some(kp)) => {
            let chain = certs_from_pem(&cp, "client certificate")?;
            if chain.is_empty() {
                return Err("client certificate PEM held no certificates".to_string());
            }
            let key = key_from_pem(&kp)?;
            Some((chain, key))
        }
        _ => None,
    };
    let client_cert_not_after = client_identity
        .as_ref()
        .and_then(|(chain, _)| chain.first())
        .and_then(|c| cert_not_after(c.as_ref()));

    // ---- provider + verifier ----
    let provider = Arc::new(provider_for(sec)?);
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls provider setup: {e}"))?;

    let verifier: Arc<dyn ServerCertVerifier> = if sec.verify_peer {
        if roots.is_empty() {
            return Err(
                "verifyPeer is on but no CA certificates were sourced (ca.secret/ca.file or a \
                 certSecret bundle with caPem)"
                    .to_string(),
            );
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("building the device-certificate verifier: {e}"))?;
        if sec.check_expiration {
            inner
        } else {
            Arc::new(ExpiryTolerantVerifier { inner })
        }
    } else {
        Arc::new(NoVerify::new(provider.clone()))
    };

    let cc = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match client_identity {
        Some((chain, key)) => cc
            .with_client_auth_cert(chain, key)
            .map_err(|e| format!("installing the client certificate/key: {e}"))?,
        None => cc.with_no_client_auth(),
    };

    let server_name = resolve_server_name(sec, conn)?;
    Ok((
        enip::TlsOptions {
            config: Arc::new(config),
            server_name,
        },
        TlsMeta {
            client_cert_not_after,
            verify_peer: sec.verify_peer,
        },
    ))
}

/// Build the protocol-agnostic [`SecurityStatus`] the seam surfaces, from the connected client's
/// negotiated TLS facts + the out-of-band [`TlsMeta`] (DESIGN-cip-security.md §3.4).
#[must_use]
pub fn security_status(
    info: Option<&enip::TlsSessionInfo>,
    meta: &TlsMeta,
    conn: &ConnectionConfig,
) -> SecurityStatus {
    let peer = info
        .and_then(|i| i.peer_cert_der.as_deref())
        .and_then(cert_subject)
        .or_else(|| Some(host_of(&conn.endpoint)));
    SecurityStatus {
        tls: true,
        tls_version: info.and_then(|i| i.protocol_version.clone()),
        cipher_suite: info.and_then(|i| i.cipher_suite.clone()),
        peer_verified: meta.verify_peer,
        peer,
        client_cert_not_after: meta.client_cert_not_after.clone(),
    }
}

/// Extract a certificate's `notAfter` as an RFC-3339 string (best-effort; `None` on any parse error).
fn cert_not_after(der: &[u8]) -> Option<String> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let secs = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    let dt = time::OffsetDateTime::from_unix_timestamp(i64::try_from(secs).ok()?).ok()?;
    dt.format(&time::format_description::well_known::Rfc3339).ok()
}

/// Extract a certificate's subject as a string (best-effort).
fn cert_subject(der: &[u8]) -> Option<String> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let s = cert.tbs_certificate.subject.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// A verifier that trusts the chain against the CA but tolerates an expired / not-yet-valid device
/// certificate (`checkExpiration: false`, for RTC-less devices) — every other check still applies.
#[derive(Debug)]
struct ExpiryTolerantVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for ExpiryTolerantVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Err(TlsError::InvalidCertificate(
                CertificateError::Expired | CertificateError::NotValidYet,
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A verifier that accepts any device certificate (`verifyPeer: false`) — it still verifies the
/// handshake signature (proving key possession) but performs no chain/name/expiry checks. A loud,
/// commissioning/debug-only posture (the adapter raises a warning + event when it is used).
#[derive(Debug)]
struct NoVerify {
    provider: Arc<CryptoProvider>,
}

impl NoVerify {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use edgecommons::credentials::{
        CredentialService, DefaultCredentialService, FileKeyProvider, KeyProvider, LocalVault,
        PutOptions,
    };
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};

    fn conn(v: serde_json::Value) -> ConnectionConfig {
        serde_json::from_value(v).unwrap()
    }

    fn sec_of(v: serde_json::Value) -> SecurityConfig {
        serde_json::from_value(v).unwrap()
    }

    // ---- config parse + validation ----

    #[test]
    fn absent_security_parses_to_none() {
        let c = conn(json!({ "endpoint": "10.0.0.1" }));
        assert!(SecurityConfig::from_connection(&c).unwrap().is_none());
    }

    #[test]
    fn plaintext_is_the_default_mode() {
        let s = sec_of(json!({}));
        assert_eq!(s.mode, SecurityMode::Plaintext);
        assert!(!s.is_tls());
        assert!(s.verify_peer, "verifyPeer defaults on");
        assert!(s.check_expiration, "checkExpiration defaults on");
    }

    #[test]
    fn tls_block_parses_from_connection() {
        let c = conn(json!({
            "endpoint": "10.0.0.1",
            "security": { "mode": "tls", "client": { "certSecret": "pki/eip" }, "ca": { "secret": "pki/root" } }
        }));
        let s = SecurityConfig::from_connection(&c).unwrap().unwrap();
        assert!(s.is_tls());
        assert_eq!(s.client.unwrap().cert_secret.as_deref(), Some("pki/eip"));
    }

    #[test]
    fn unknown_security_key_is_rejected() {
        let c = conn(json!({ "endpoint": "h", "security": { "mode": "tls", "bogus": 1 } }));
        assert!(SecurityConfig::from_connection(&c).is_err());
    }

    #[test]
    fn tls_on_push_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "x" }, "ca": { "secret": "y" } }));
        let err = s.validate("io-1", true).unwrap_err();
        assert!(err.contains("push"), "{err}");
        assert!(err.contains("DTLS"), "{err}");
    }

    #[test]
    fn tls_without_client_identity_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "ca": { "secret": "y" } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("client identity"), "{err}");
    }

    #[test]
    fn tls_with_partial_file_identity_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "client": { "certFile": "c.pem" }, "verifyPeer": false }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("BOTH certFile and keyFile"), "{err}");
    }

    #[test]
    fn tls_verify_peer_without_ca_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "client": { "certFile": "c.pem", "keyFile": "k.pem" } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("CA source"), "{err}");
    }

    #[test]
    fn tls_verify_peer_false_without_ca_is_allowed() {
        let s = sec_of(json!({ "mode": "tls", "client": { "certFile": "c.pem", "keyFile": "k.pem" }, "verifyPeer": false }));
        assert!(s.validate("plc", false).is_ok());
    }

    #[test]
    fn tls_with_cert_secret_bundle_satisfies_ca_requirement() {
        // certSecret may carry caPem, so verifyPeer is allowed without an explicit ca block.
        let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "pki/eip" } }));
        assert!(s.validate("plc", false).is_ok());
    }

    #[test]
    fn plaintext_validate_is_noop() {
        assert!(sec_of(json!({})).validate("plc", false).is_ok());
        assert!(sec_of(json!({})).validate("io", true).is_ok());
    }

    // ---- server-name resolution ----

    #[test]
    fn server_name_defaults_to_endpoint_ip_as_ip_san() {
        let c = conn(json!({ "endpoint": "192.168.10.60:2221" }));
        let s = sec_of(json!({ "mode": "tls" }));
        let name = resolve_server_name(&s, &c).unwrap();
        assert!(matches!(name, ServerName::IpAddress(_)), "IP endpoint ⇒ IP SAN name");
    }

    #[test]
    fn server_name_override_dns() {
        let c = conn(json!({ "endpoint": "10.0.0.1" }));
        let s = sec_of(json!({ "mode": "tls", "serverName": "plc.plant.example" }));
        let name = resolve_server_name(&s, &c).unwrap();
        assert!(matches!(name, ServerName::DnsName(_)));
    }

    #[test]
    fn host_of_strips_port_keeps_bare_host() {
        assert_eq!(host_of("192.168.1.5:44818"), "192.168.1.5");
        assert_eq!(host_of("plc.example"), "plc.example");
        assert_eq!(host_of("[fe80::1]:2221"), "fe80::1");
    }

    // ---- a real cert fixture, minted with rcgen, used across the build tests ----

    struct Fx {
        ca_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn mint() -> Fx {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let cp = CertificateParams::new(vec!["eip-originator".to_string()]).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        Fx {
            ca_pem: ca_cert.pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    fn vault_with(bundle_name: &str, ca_name: &str, fx: &Fx) -> Arc<dyn CredentialService> {
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(FileKeyProvider::from_bytes([7u8; 32])) as Arc<dyn KeyProvider>;
        let vault = LocalVault::open(dir.path().join("vault"), provider, 2).unwrap();
        let svc = DefaultCredentialService::new(vault);
        // Store the client identity as a TLS bundle and the CA as a PEM string secret.
        let bundle = json!({
            "certPem": fx.client_cert_pem, "keyPem": fx.client_key_pem, "caPem": fx.ca_pem
        });
        svc.put(
            bundle_name,
            serde_json::to_vec(&bundle).unwrap().as_slice(),
            PutOptions::default(),
        )
        .unwrap();
        svc.put(ca_name, fx.ca_pem.as_bytes(), PutOptions::default())
            .unwrap();
        // Keep the tempdir alive for the vault's lifetime by leaking it (test-only).
        std::mem::forget(dir);
        Arc::new(svc)
    }

    #[test]
    fn build_client_config_from_vault_bundle_and_ca() {
        let fx = mint();
        let creds = vault_with("pki/eip", "pki/root", &fx);
        let c = conn(json!({ "endpoint": "127.0.0.1:2221" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certSecret": "pki/eip" },
            "ca": { "secret": "pki/root" }
        }));
        let (opts, meta) = build_client_config(&s, &c, Some(&creds)).unwrap();
        assert!(matches!(opts.server_name, ServerName::IpAddress(_)));
        assert!(meta.verify_peer);
        assert!(meta.client_cert_not_after.is_some(), "client cert notAfter parsed");
    }

    #[test]
    fn build_client_config_from_files() {
        use std::io::Write;
        let fx = mint();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        let ca_path = dir.path().join("ca.pem");
        std::fs::File::create(&cert_path).unwrap().write_all(fx.client_cert_pem.as_bytes()).unwrap();
        std::fs::File::create(&key_path).unwrap().write_all(fx.client_key_pem.as_bytes()).unwrap();
        std::fs::File::create(&ca_path).unwrap().write_all(fx.ca_pem.as_bytes()).unwrap();

        let c = conn(json!({ "endpoint": "127.0.0.1:2221" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certFile": cert_path.to_str().unwrap(), "keyFile": key_path.to_str().unwrap() },
            "ca": { "file": ca_path.to_str().unwrap() }
        }));
        let (_opts, meta) = build_client_config(&s, &c, None).unwrap();
        assert!(meta.client_cert_not_after.is_some());
    }

    #[test]
    fn build_no_verify_needs_no_ca_and_reports_unverified() {
        let fx = mint();
        let creds = vault_with("pki/eip", "pki/root", &fx);
        let c = conn(json!({ "endpoint": "127.0.0.1:2221" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certSecret": "pki/eip" },
            "verifyPeer": false
        }));
        let (_opts, meta) = build_client_config(&s, &c, Some(&creds)).unwrap();
        assert!(!meta.verify_peer);
    }

    #[test]
    fn build_verify_peer_without_any_ca_errors() {
        // verifyPeer with a file identity and no CA anywhere ⇒ the builder refuses.
        use std::io::Write;
        let fx = mint();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        std::fs::File::create(&cert_path).unwrap().write_all(fx.client_cert_pem.as_bytes()).unwrap();
        std::fs::File::create(&key_path).unwrap().write_all(fx.client_key_pem.as_bytes()).unwrap();
        let c = conn(json!({ "endpoint": "127.0.0.1:2221" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certFile": cert_path.to_str().unwrap(), "keyFile": key_path.to_str().unwrap() }
        }));
        let err = build_client_config(&s, &c, None).unwrap_err();
        assert!(err.contains("no CA"), "{err}");
    }

    #[test]
    fn cert_secret_missing_from_vault_errors() {
        let fx = mint();
        let creds = vault_with("pki/eip", "pki/root", &fx);
        let c = conn(json!({ "endpoint": "127.0.0.1" }));
        let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "pki/absent" }, "verifyPeer": false }));
        let err = build_client_config(&s, &c, Some(&creds)).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn cert_secret_without_vault_errors() {
        let c = conn(json!({ "endpoint": "h" }));
        let s = sec_of(json!({ "mode": "tls", "client": { "certSecret": "pki/eip" }, "verifyPeer": false }));
        let err = build_client_config(&s, &c, None).unwrap_err();
        assert!(err.contains("no credentials vault"), "{err}");
    }

    #[test]
    fn cipher_suite_constraint_accepts_a_known_gcm_suite() {
        let fx = mint();
        let creds = vault_with("pki/eip", "pki/root", &fx);
        let c = conn(json!({ "endpoint": "127.0.0.1" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certSecret": "pki/eip" },
            "verifyPeer": false,
            "cipherSuites": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS13_AES_128_GCM_SHA256"]
        }));
        assert!(build_client_config(&s, &c, Some(&creds)).is_ok());
    }

    #[test]
    fn cipher_suite_constraint_rejecting_all_suites_errors() {
        let fx = mint();
        let creds = vault_with("pki/eip", "pki/root", &fx);
        let c = conn(json!({ "endpoint": "127.0.0.1" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": { "certSecret": "pki/eip" },
            "verifyPeer": false,
            "cipherSuites": ["TLS_RSA_WITH_AES_128_CBC_SHA256"]
        }));
        let err = build_client_config(&s, &c, Some(&creds)).unwrap_err();
        assert!(err.contains("matched no supported suite"), "{err}");
    }

    #[test]
    fn security_status_renders_from_session_info() {
        let info = enip::TlsSessionInfo {
            protocol_version: Some("1.3".to_string()),
            cipher_suite: Some("TLS13_AES_128_GCM_SHA256".to_string()),
            peer_cert_der: None,
        };
        let meta = TlsMeta { client_cert_not_after: Some("2027-01-01T00:00:00Z".to_string()), verify_peer: true };
        let c = conn(json!({ "endpoint": "192.168.10.60:2221" }));
        let st = security_status(Some(&info), &meta, &c);
        assert!(st.tls);
        assert_eq!(st.tls_version.as_deref(), Some("1.3"));
        assert_eq!(st.cipher_suite.as_deref(), Some("TLS13_AES_128_GCM_SHA256"));
        assert!(st.peer_verified);
        assert_eq!(st.peer.as_deref(), Some("192.168.10.60"), "falls back to endpoint host");
        assert_eq!(st.client_cert_not_after.as_deref(), Some("2027-01-01T00:00:00Z"));
    }

    #[test]
    fn cert_not_after_parses_a_real_cert() {
        let fx = mint();
        let der = certs_from_pem(&fx.client_cert_pem, "client").unwrap();
        assert!(cert_not_after(der[0].as_ref()).is_some());
        assert!(cert_subject(der[0].as_ref()).is_some());
    }

    #[test]
    fn no_verify_verifier_supports_schemes() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = NoVerify::new(provider);
        assert!(!v.supported_verify_schemes().is_empty());
        let _ = IpAddr::V4(Ipv4Addr::LOCALHOST); // touch import
    }
}
