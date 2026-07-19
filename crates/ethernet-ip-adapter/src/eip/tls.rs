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

use crate::device::{
    ConnectionConfig, SecurityStatus, TargetCertificateSummary, TargetSecurityPosture,
};

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

/// An inline `{"$secret": "<name>"[, "field": "<key>"]}` content reference — the ecosystem's
/// universal `$secret` convention (`core/docs/CREDENTIALS.md`), resolved to PEM text at connect time.
/// The whole-secret form yields the secret's UTF-8 value; the `field` form yields that JSON field of
/// the secret. Distinct on the wire from a `*Secret` typed vault ref (a bare string) and a `*File`
/// path (a bare string): this is always a JSON object with a `$secret` key.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// The vault secret name.
    #[serde(rename = "$secret")]
    pub secret: String,
    /// An optional JSON field of the secret to read (whole value when absent).
    #[serde(default)]
    pub field: Option<String>,
}

impl SecretRef {
    /// Resolve the reference to PEM text via the vault. `what` names the credential for errors.
    ///
    /// # Errors
    ///
    /// A config-legible message when no vault is configured, the secret is absent, or the requested
    /// field is missing / not a string.
    fn resolve(
        &self,
        creds: Option<&Arc<dyn CredentialService>>,
        what: &str,
    ) -> std::result::Result<String, String> {
        let creds = creds.ok_or_else(|| {
            format!(
                "{what} uses {{\"$secret\": \"{}\"}} but no credentials vault is configured",
                self.secret
            )
        })?;
        let secret = creds
            .get(&self.secret)
            .map_err(|e| format!("vault get(`{}`) for {what}: {e}", self.secret))?
            .ok_or_else(|| format!("vault secret `{}` (referenced by {what}) not found", self.secret))?;
        match &self.field {
            None => secret
                .as_str()
                .map(str::to_string)
                .map_err(|e| format!("secret `{}` for {what}: {e}", self.secret)),
            Some(f) => secret
                .as_json()
                .map_err(|e| format!("secret `{}` for {what}: {e}", self.secret))?
                .get(f)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| {
                    format!("secret `{}` field `{f}` (for {what}) missing or not a string", self.secret)
                }),
        }
    }
}

/// The adapter's client identity for mutual TLS. Exactly one of three sourcing **styles** is given
/// (validated in [`SecurityConfig::validate`], §3.3):
///
/// 1. **bundle vault ref** — `certSecret`: a vault `{certPem, keyPem[, caPem]}` TLS bundle (one ref
///    yields cert + key together);
/// 2. **files** — `certFile` + `keyFile`: PEM file paths (both required);
/// 3. **inline `$secret` content** — `cert` + `key`: each a `{"$secret": …}` yielding one PEM (both
///    required), the ecosystem `$secret` convention.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientIdentity {
    /// Style 1: a vault secret name holding a `{certPem, keyPem[, caPem]}` TLS bundle.
    #[serde(default)]
    pub cert_secret: Option<String>,
    /// Style 2: a PEM certificate (chain) file path.
    #[serde(default)]
    pub cert_file: Option<String>,
    /// Style 2: a PEM private-key file path.
    #[serde(default)]
    pub key_file: Option<String>,
    /// Style 3: an inline `{"$secret": …}` yielding the client certificate (chain) PEM.
    #[serde(default)]
    pub cert: Option<SecretRef>,
    /// Style 3: an inline `{"$secret": …}` yielding the client private-key PEM.
    #[serde(default)]
    pub key: Option<SecretRef>,
}

impl ClientIdentity {
    /// Whether the bundle (`certSecret`) style is used.
    fn has_bundle(&self) -> bool {
        self.cert_secret.is_some()
    }
    /// Whether any file field is set.
    fn has_files(&self) -> bool {
        self.cert_file.is_some() || self.key_file.is_some()
    }
    /// Whether any inline `$secret` field is set.
    fn has_inline(&self) -> bool {
        self.cert.is_some() || self.key.is_some()
    }
}

/// The trust anchors for verifying the device certificate. Exactly one of three sourcing styles:
/// a vault secret name (`secret`), a PEM file path (`file`), or an inline `{"$secret": …}` (`cert`)
/// — the `client`-identity styles' CA analog (§3.3/§4.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaSource {
    /// A vault secret name holding CA certificate PEM.
    #[serde(default)]
    pub secret: Option<String>,
    /// A CA PEM file path.
    #[serde(default)]
    pub file: Option<String>,
    /// An inline `{"$secret": …}` yielding the CA certificate PEM (one or more roots).
    #[serde(default)]
    pub cert: Option<SecretRef>,
}

impl CaSource {
    /// The number of sourcing styles configured (should be exactly one).
    fn style_count(&self) -> usize {
        usize::from(self.secret.is_some())
            + usize::from(self.file.is_some())
            + usize::from(self.cert.is_some())
    }
    /// Whether any CA source is configured at all.
    fn is_configured(&self) -> bool {
        self.style_count() > 0
    }
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
        // The client identity is sourced by exactly ONE of three styles — bundle (certSecret), files
        // (certFile+keyFile), or inline (cert+key {"$secret": …}). Mixing them is ambiguous (which
        // wins?), so it is a startup error, and each chosen style must be complete.
        if let Some(c) = &self.client {
            let styles =
                usize::from(c.has_bundle()) + usize::from(c.has_files()) + usize::from(c.has_inline());
            if styles > 1 {
                return Err(format!(
                    "device `{device_id}`: security.client mixes sourcing styles — use exactly ONE of \
                     certSecret (vault bundle), certFile+keyFile (files), or cert+key inline \
                     {{\"$secret\": …}}"
                ));
            }
            // A partial file identity (only one of certFile/keyFile) is a specific, common mistake.
            if c.has_files() && !(c.cert_file.is_some() && c.key_file.is_some()) {
                return Err(format!(
                    "device `{device_id}`: security.client needs BOTH certFile and keyFile"
                ));
            }
            // Likewise a partial inline identity (only one of cert/key).
            if c.has_inline() && !(c.cert.is_some() && c.key.is_some()) {
                return Err(format!(
                    "device `{device_id}`: security.client needs BOTH cert and key inline \
                     {{\"$secret\": …}} references"
                ));
            }
        }
        // A CIP Security device requires a client certificate (0x5E attr 9), so an identity-less TLS
        // config is almost certainly a misconfiguration.
        let has_client = self.client.as_ref().is_some_and(|c| {
            c.has_bundle()
                || (c.cert_file.is_some() && c.key_file.is_some())
                || (c.cert.is_some() && c.key.is_some())
        });
        if !has_client {
            return Err(format!(
                "device `{device_id}`: security.mode `tls` requires a client identity \
                 (client.certSecret, client.certFile + client.keyFile, or client.cert + client.key \
                 inline {{\"$secret\": …}})"
            ));
        }
        // The CA source is likewise exactly one style (secret / file / cert inline) when present.
        if let Some(ca) = &self.ca {
            if ca.style_count() > 1 {
                return Err(format!(
                    "device `{device_id}`: security.ca mixes sourcing styles — use exactly ONE of \
                     secret (vault), file (path), or cert inline {{\"$secret\": …}}"
                ));
            }
        }
        // Verifying the peer needs trust anchors — either an explicit ca source (any style), or a
        // certSecret bundle that may carry caPem (resolved at connect time).
        if self.verify_peer {
            let has_ca = self.ca.as_ref().is_some_and(CaSource::is_configured);
            let bundle_may_have_ca = self.client.as_ref().is_some_and(ClientIdentity::has_bundle);
            if !has_ca && !bundle_may_have_ca {
                return Err(format!(
                    "device `{device_id}`: security.mode `tls` with verifyPeer requires a CA source \
                     (ca.secret, ca.file, or ca.cert inline {{\"$secret\": …}}) unless the client \
                     bundle (certSecret) carries caPem"
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

    // ---- client identity (exactly one style, per validate()) ----
    if let Some(c) = &sec.client {
        if let Some(name) = &c.cert_secret {
            // Style 1: a vault TLS bundle (cert + key + optional CA together).
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
        } else if let (Some(cert), Some(key)) = (&c.cert, &c.key) {
            // Style 3: inline {"$secret": …} refs, each resolved to one PEM.
            client_cert_pem = Some(cert.resolve(creds, "client.cert")?);
            client_key_pem = Some(key.resolve(creds, "client.key")?);
        } else if let (Some(cf), Some(kf)) = (&c.cert_file, &c.key_file) {
            // Style 2: file paths.
            client_cert_pem = Some(read_pem_file(cf, "client certificate")?);
            client_key_pem = Some(read_pem_file(kf, "client key")?);
        }
    }

    // ---- trust anchors (exactly one style, per validate()) ----
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
        } else if let Some(cert) = &ca.cert {
            // Inline {"$secret": …} CA content.
            root_pems.push(cert.resolve(creds, "ca.cert")?);
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
        target: None,
    }
}

/// A plaintext-session [`SecurityStatus`] carrying (only) the target's posture — so a `mode:
/// plaintext` instance that read a target's CIP Security objects still surfaces them (and reports
/// `targetSupportsCipSecurity`). `tls: false` marks the session plaintext.
#[must_use]
pub fn plaintext_status(target: Option<TargetSecurityPosture>) -> SecurityStatus {
    SecurityStatus {
        tls: false,
        target,
        ..SecurityStatus::default()
    }
}

/// Map the `enip` crate's decoded [`enip::SecurityPosture`] into the protocol-agnostic seam
/// [`TargetSecurityPosture`] (Phase 2a, §4.1). `None` when the device implements no CIP Security
/// object — the seam never sees the `enip` types.
#[must_use]
pub fn map_target_posture(p: &enip::SecurityPosture) -> Option<TargetSecurityPosture> {
    if !p.is_available() {
        return None;
    }
    let mut out = TargetSecurityPosture::default();
    if let Some(cip) = &p.cip_security {
        out.state = Some(cip.state.description().to_string());
        if let Some(prof) = &cip.profiles_supported {
            out.profiles = prof.names().into_iter().map(String::from).collect();
        }
    }
    if let Some(eip) = &p.eip_security {
        if let Some(a) = &eip.allowed_cipher_suites {
            out.allowed_cipher_suites = a.labels();
        }
        if let Some(a) = &eip.available_cipher_suites {
            out.available_cipher_suites = a.labels();
        }
        out.verify_client = eip.verify_client_certificate;
        out.send_certificate_chain = eip.send_certificate_chain;
        out.check_expiration = eip.check_expiration;
    }
    if let Some(cert) = &p.certificate_management {
        let mut cs = TargetCertificateSummary::default();
        if let Some(caps) = &cert.capabilities {
            cs.push_supported = Some(caps.push_supported());
            cs.pull_supported = Some(caps.pull_supported());
        }
        if let Some(inst) = &cert.instance1 {
            cs.name = inst.name.clone();
            cs.state = inst.state.map(|s| s.description().to_string());
            cs.encoding = inst.encoding.map(|e| e.description().to_string());
        }
        out.certificate = Some(cs);
    }
    Some(out)
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

    // ---- Change 1: inline `$secret` sourcing style + collision rejection ----

    #[test]
    fn tls_inline_secret_client_and_ca_parse_and_validate() {
        let c = conn(json!({
            "endpoint": "10.0.0.1",
            "security": {
                "mode": "tls",
                "client": {
                    "cert": { "$secret": "tls/cip-client-cert" },
                    "key": { "$secret": "tls/cip-client-key" }
                },
                "ca": { "cert": { "$secret": "tls/plant-root" } }
            }
        }));
        let s = SecurityConfig::from_connection(&c).unwrap().unwrap();
        let client = s.client.as_ref().unwrap();
        assert_eq!(client.cert.as_ref().unwrap().secret, "tls/cip-client-cert");
        assert_eq!(client.key.as_ref().unwrap().secret, "tls/cip-client-key");
        assert_eq!(s.ca.as_ref().unwrap().cert.as_ref().unwrap().secret, "tls/plant-root");
        assert!(s.validate("plc", false).is_ok());
    }

    #[test]
    fn secret_ref_field_form_parses() {
        let c = conn(json!({
            "endpoint": "h",
            "security": { "mode": "tls",
                "client": { "cert": { "$secret": "bundle", "field": "certPem" },
                            "key": { "$secret": "bundle", "field": "keyPem" } },
                "verifyPeer": false }
        }));
        let s = SecurityConfig::from_connection(&c).unwrap().unwrap();
        let key = s.client.unwrap().key.unwrap();
        assert_eq!(key.secret, "bundle");
        assert_eq!(key.field.as_deref(), Some("keyPem"));
    }

    #[test]
    fn client_mixing_bundle_and_inline_is_rejected() {
        let s = sec_of(json!({ "mode": "tls",
            "client": { "certSecret": "pki/eip", "cert": { "$secret": "x" }, "key": { "$secret": "y" } } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("mixes sourcing styles"), "{err}");
    }

    #[test]
    fn client_mixing_files_and_inline_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "verifyPeer": false,
            "client": { "certFile": "c.pem", "keyFile": "k.pem", "cert": { "$secret": "x" }, "key": { "$secret": "y" } } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("mixes sourcing styles"), "{err}");
    }

    #[test]
    fn client_partial_inline_identity_is_rejected() {
        let s = sec_of(json!({ "mode": "tls", "verifyPeer": false,
            "client": { "cert": { "$secret": "x" } } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("BOTH cert and key inline"), "{err}");
    }

    #[test]
    fn ca_mixing_file_and_inline_is_rejected() {
        let s = sec_of(json!({ "mode": "tls",
            "client": { "certFile": "c.pem", "keyFile": "k.pem" },
            "ca": { "file": "ca.pem", "cert": { "$secret": "root" } } }));
        let err = s.validate("plc", false).unwrap_err();
        assert!(err.contains("security.ca mixes sourcing styles"), "{err}");
    }

    #[test]
    fn ca_inline_secret_satisfies_verify_peer() {
        let s = sec_of(json!({ "mode": "tls",
            "client": { "certFile": "c.pem", "keyFile": "k.pem" },
            "ca": { "cert": { "$secret": "root" } } }));
        assert!(s.validate("plc", false).is_ok());
    }

    #[test]
    fn unknown_key_in_secret_ref_is_rejected() {
        // The inline object is strict: only `$secret` and `field` are allowed.
        let c = conn(json!({ "endpoint": "h", "security": { "mode": "tls",
            "client": { "cert": { "$secret": "x", "bogus": 1 }, "key": { "$secret": "y" } } } }));
        assert!(SecurityConfig::from_connection(&c).is_err());
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

    /// A vault holding the cert / key / CA as three separate plain-PEM string secrets (the inline
    /// `$secret` style stores each credential independently, not as a bundle).
    fn vault_with_items(fx: &Fx) -> Arc<dyn CredentialService> {
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(FileKeyProvider::from_bytes([9u8; 32])) as Arc<dyn KeyProvider>;
        let vault = LocalVault::open(dir.path().join("vault"), provider, 2).unwrap();
        let svc = DefaultCredentialService::new(vault);
        svc.put("tls/cip-client-cert", fx.client_cert_pem.as_bytes(), PutOptions::default()).unwrap();
        svc.put("tls/cip-client-key", fx.client_key_pem.as_bytes(), PutOptions::default()).unwrap();
        svc.put("tls/plant-root", fx.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        std::mem::forget(dir);
        Arc::new(svc)
    }

    #[test]
    fn build_client_config_from_inline_secret_cert_key_and_ca() {
        let fx = mint();
        let creds = vault_with_items(&fx);
        let c = conn(json!({ "endpoint": "127.0.0.1:2221" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": {
                "cert": { "$secret": "tls/cip-client-cert" },
                "key": { "$secret": "tls/cip-client-key" }
            },
            "ca": { "cert": { "$secret": "tls/plant-root" } }
        }));
        let (opts, meta) = build_client_config(&s, &c, Some(&creds)).unwrap();
        assert!(matches!(opts.server_name, ServerName::IpAddress(_)));
        assert!(meta.verify_peer);
        assert!(meta.client_cert_not_after.is_some(), "inline client cert notAfter parsed");
    }

    #[test]
    fn build_inline_secret_field_form_reads_a_bundle_field() {
        // Store a JSON bundle and reference individual fields via `{"$secret": …, "field": …}`.
        let fx = mint();
        let dir = tempfile::tempdir().unwrap();
        let provider = Arc::new(FileKeyProvider::from_bytes([3u8; 32])) as Arc<dyn KeyProvider>;
        let vault = LocalVault::open(dir.path().join("vault"), provider, 2).unwrap();
        let svc = DefaultCredentialService::new(vault);
        let bundle = json!({ "certPem": fx.client_cert_pem, "keyPem": fx.client_key_pem });
        svc.put("tls/bundle", serde_json::to_vec(&bundle).unwrap().as_slice(), PutOptions::default()).unwrap();
        svc.put("tls/root", fx.ca_pem.as_bytes(), PutOptions::default()).unwrap();
        std::mem::forget(dir);
        let creds: Arc<dyn CredentialService> = Arc::new(svc);

        let c = conn(json!({ "endpoint": "127.0.0.1" }));
        let s = sec_of(json!({
            "mode": "tls",
            "client": {
                "cert": { "$secret": "tls/bundle", "field": "certPem" },
                "key": { "$secret": "tls/bundle", "field": "keyPem" }
            },
            "ca": { "cert": { "$secret": "tls/root" } }
        }));
        let (_opts, meta) = build_client_config(&s, &c, Some(&creds)).unwrap();
        assert!(meta.client_cert_not_after.is_some());
    }

    #[test]
    fn build_inline_secret_without_vault_errors() {
        let c = conn(json!({ "endpoint": "h" }));
        let s = sec_of(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/c" }, "key": { "$secret": "tls/k" } },
            "verifyPeer": false }));
        let err = build_client_config(&s, &c, None).unwrap_err();
        assert!(err.contains("no credentials vault"), "{err}");
    }

    #[test]
    fn build_inline_secret_missing_from_vault_errors() {
        let fx = mint();
        let creds = vault_with_items(&fx);
        let c = conn(json!({ "endpoint": "h" }));
        let s = sec_of(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/absent" }, "key": { "$secret": "tls/cip-client-key" } },
            "verifyPeer": false }));
        let err = build_client_config(&s, &c, Some(&creds)).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn build_inline_secret_missing_field_errors() {
        let fx = mint();
        let creds = vault_with_items(&fx);
        let c = conn(json!({ "endpoint": "h" }));
        // `tls/plant-root` is a bare PEM (not JSON), so a field read fails legibly.
        let s = sec_of(json!({ "mode": "tls",
            "client": { "cert": { "$secret": "tls/plant-root", "field": "certPem" },
                        "key": { "$secret": "tls/cip-client-key" } },
            "verifyPeer": false }));
        let err = build_client_config(&s, &c, Some(&creds)).unwrap_err();
        assert!(err.contains("client.cert"), "{err}");
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

    // ---- Phase 2a: enip posture → seam mapping ----

    #[test]
    fn map_target_posture_maps_a_full_posture() {
        let posture = enip::SecurityPosture {
            cip_security: Some(enip::CipSecurityObject {
                state: enip::CipSecurityState::Configured,
                profiles_supported: Some(enip::SecurityProfiles { bits: 0x0002 }),
                profiles_configured: None,
            }),
            eip_security: Some(enip::EipSecurityObject {
                state: 2,
                capability_flags: None,
                available_cipher_suites: Some(enip::CipherSuiteList {
                    suites: vec![enip::CipherSuiteId { id: 0xC02B }],
                }),
                allowed_cipher_suites: Some(enip::CipherSuiteList {
                    suites: vec![enip::CipherSuiteId { id: 0xC02B }],
                }),
                verify_client_certificate: Some(true),
                send_certificate_chain: Some(false),
                check_expiration: Some(true),
            }),
            certificate_management: Some(enip::CertificateManagementSummary {
                capabilities: Some(enip::CertificateCapabilities { flags: 0x0000_0001 }),
                instance1: Some(enip::CertificateInstance {
                    name: Some("Device".to_string()),
                    state: Some(enip::CertificateState::Verified),
                    encoding: Some(enip::CertificateEncoding::Pem),
                }),
            }),
        };
        let mapped = map_target_posture(&posture).expect("available posture maps");
        assert_eq!(mapped.state.as_deref(), Some("Configured"));
        assert_eq!(mapped.profiles, vec!["EtherNet/IP Confidentiality".to_string()]);
        assert_eq!(
            mapped.allowed_cipher_suites,
            vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string()]
        );
        assert_eq!(mapped.verify_client, Some(true));
        let cert = mapped.certificate.expect("cert summary");
        assert_eq!(cert.push_supported, Some(true));
        assert_eq!(cert.pull_supported, Some(false));
        assert_eq!(cert.name.as_deref(), Some("Device"));
        assert_eq!(cert.state.as_deref(), Some("Verified"));
        assert_eq!(cert.encoding.as_deref(), Some("PEM"));
    }

    #[test]
    fn map_target_posture_none_for_empty() {
        assert!(map_target_posture(&enip::SecurityPosture::default()).is_none());
    }

    #[test]
    fn plaintext_status_carries_only_the_target() {
        let st = plaintext_status(Some(TargetSecurityPosture {
            state: Some("Factory Default".to_string()),
            ..Default::default()
        }));
        assert!(!st.tls);
        assert!(st.target.is_some());
        assert!(st.tls_version.is_none());
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
