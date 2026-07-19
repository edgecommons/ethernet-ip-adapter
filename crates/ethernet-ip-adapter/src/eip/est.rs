//! # CIP Security Phase 2c — EST (Enrollment over Secure Transport, RFC 7030) client
//!
//! The adapter's TLS material (Phase 1/2b) has so far been **hand-provisioned** into the credentials
//! vault. Phase 2c closes the loop: when `connection.security.est.enabled` is set, the adapter obtains
//! and renews its own client certificate **automatically** from a plant EST server (RFC 7030), writing
//! the enrolled key+cert back into the same vault secret Phase 2b already watches — so the existing
//! [`super::rotation`] watcher detects the change and reconnects with the new material, no restart.
//!
//! This is **adapter business, not EtherNet/IP protocol** (DESIGN-cip-security.md §4.3, D-EIP-24): EST
//! is credential *provisioning* over HTTPS, so it lives here and the `enip` crate is untouched. The
//! client is a **thin owned RFC 7030 client** (the spike's decision — no dependency on the immature
//! `est-ca` crate) composed from crates the adapter already trusts:
//!
//! * [`rcgen`] — generate the P-256 keypair + PKCS#10 CSR (ring backend, no C);
//! * [`tokio_rustls`] — the HTTPS transport (the Phase-1 rustls/ring stack, authenticated as
//!   configured: TLS client cert for re-enroll, an inline bootstrap identity, or HTTP Basic);
//! * [`cms`] + [`x509_cert`] — parse the `application/pkcs7-mime` (certs-only degenerate SignedData)
//!   response to extract the issued certificate;
//! * [`base64`] — the `application/pkcs10` CSR body and the PKCS#7 reply are base64 on the wire.
//!
//! **Everything is bounds-checked and typed; there is no `unsafe`.** The pure pieces — config
//! parse/validate, URL parsing, CSR generation, request encoding, HTTP-response and PKCS#7 parsing, the
//! renew-window decision, and the vault write-back — are unit-tested (incl. a golden PKCS#7 vector);
//! the socket-driving [`EstClient::request_certificate`] is exercised by an in-process rustls EST
//! responder in the unit tests and, live, by `tests/live_est.rs` against a real EST server.
//!
//! EST is **OFF by default and severable**: absent the `est` block (or with `enabled: false`) nothing
//! here runs and a plaintext/no-EST deployment is unaffected.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use edgecommons::credentials::CredentialService;

use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use super::tls::{
    certs_from_pem, key_from_pem, source_ca_pems, source_client_material, CaSource, ClientIdentity,
    SecretRef, SecurityConfig, DEFAULT_RENEW_BEFORE_DAYS,
};

/// The default `retryBackoffMins` between failed enrollment attempts.
pub const DEFAULT_RETRY_BACKOFF_MINS: u64 = 60;
/// The CSR subject CommonName used when `est.subject` is unset.
pub const DEFAULT_SUBJECT_CN: &str = "eip-originator";
/// Hard cap on an EST HTTP response body (defensive bound; certs-only PKCS#7 replies are a few KiB).
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------------------------------
// Config surface (`connection.security.est`)
// ---------------------------------------------------------------------------------------------------

/// The `connection.security.est` block (DESIGN-cip-security.md §4.3) — a strict typed island, OFF
/// unless `enabled: true`. Parsed as part of [`SecurityConfig`]; validated by [`EstConfig::validate`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EstConfig {
    /// `true` ⇒ the adapter enrolls/renews its client certificate via EST. Default `false` (severable).
    #[serde(default)]
    pub enabled: bool,
    /// The EST server base URL, e.g. `https://est.plant.example:8085/.well-known/est`. Required when
    /// `enabled`. Must be `https://`.
    #[serde(default)]
    pub server: Option<String>,
    /// An optional EST label path segment (RFC 7030 §3.2.2), inserted before the operation, e.g.
    /// `.../.well-known/est/<label>/simpleenroll`.
    #[serde(default)]
    pub label: Option<String>,
    /// Trust anchors for verifying the **EST server's** TLS certificate (a [`CaSource`], any style).
    /// When absent, the connection's `security.ca` trust store is reused.
    #[serde(default)]
    pub trust: Option<CaSource>,
    /// How the adapter authenticates to the EST server. When absent, the connection's current client
    /// identity is reused (mutual-TLS re-enroll).
    #[serde(default)]
    pub auth: Option<EstAuth>,
    /// Where the enrolled key+certificate are written back into the vault. When absent, the destination
    /// is derived from `security.client` (so Phase 2b's watcher reloads it).
    #[serde(default)]
    pub into: Option<EstDestination>,
    /// The CSR subject CommonName. Default [`DEFAULT_SUBJECT_CN`].
    #[serde(default)]
    pub subject: Option<String>,
    /// Renew the certificate this many days before `notAfter`. Default = `client.renewBeforeDays` or
    /// [`DEFAULT_RENEW_BEFORE_DAYS`].
    #[serde(default)]
    pub renew_before_days: Option<u32>,
    /// Minimum minutes between failed enrollment attempts (offline-first backoff). Default
    /// [`DEFAULT_RETRY_BACKOFF_MINS`].
    #[serde(default)]
    pub retry_backoff_mins: Option<u64>,
    /// Fetch the EST server's CA bag via `GET /cacerts` before enrolling, to confirm/bootstrap trust
    /// (RFC 7030 §4.1). Default `false`. The fetched roots are logged (and count-compared to the
    /// configured trust); enrollment then proceeds against the configured trust anchors.
    #[serde(default)]
    pub fetch_ca_certs: bool,
}

/// How the adapter authenticates to the EST server (DESIGN-cip-security.md §4.3). Exactly one of
/// `bootstrap` / `basic` is given, or neither (⇒ reuse the connection's current client identity for a
/// mutual-TLS re-enroll).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EstAuth {
    /// A bootstrap client identity (vendor / self-signed / prior cert) used for the **initial** enroll,
    /// sourced exactly like `security.client` (bundle / files / inline `{"$secret": …}`).
    #[serde(default)]
    pub bootstrap: Option<ClientIdentity>,
    /// HTTP Basic credentials — an inline `{"$secret": …}` reference to a vault `{username, password}`
    /// secret. Sent as an `Authorization: Basic` header (over TLS).
    #[serde(default)]
    pub basic: Option<SecretRef>,
}

/// Where the enrolled material is written back into the vault (DESIGN-cip-security.md §4.3). Exactly
/// one style; when absent the destination is derived from `security.client` so Phase 2b reloads it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EstDestination {
    /// Write a `{certPem, keyPem}` TLS bundle to this single vault secret (the `client.certSecret` shape).
    #[serde(default)]
    pub cert_secret: Option<String>,
    /// Write the certificate (chain) PEM to this vault secret (the inline-`$secret` shape); pairs with `key`.
    #[serde(default)]
    pub cert: Option<String>,
    /// Write the private-key PEM to this vault secret; pairs with `cert`.
    #[serde(default)]
    pub key: Option<String>,
}

/// The resolved vault write-back target: either one bundle secret, or a (cert, key) secret pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedDestination {
    /// A single secret holding a `{certPem, keyPem}` JSON bundle.
    Bundle(String),
    /// Separate cert-PEM and key-PEM secrets.
    Pair { cert: String, key: String },
}

impl EstConfig {
    /// Fail-fast startup validation (DESIGN-cip-security.md §4.3). A no-op when `!enabled`.
    ///
    /// # Errors
    ///
    /// A config-legible message when `enabled` but the server URL is missing/not-https, the auth
    /// styles collide, a bootstrap identity is incomplete, or the write-back destination cannot be
    /// determined.
    pub fn validate(&self, device_id: &str, sec: &SecurityConfig) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let server = self.server.as_deref().ok_or_else(|| {
            format!("device `{device_id}`: security.est.enabled requires est.server (the EST server URL)")
        })?;
        if !server.starts_with("https://") {
            return Err(format!(
                "device `{device_id}`: security.est.server `{server}` must be an https:// URL"
            ));
        }
        // The URL must parse (host + optional port + path).
        EstEndpoint::parse(server, self.label.as_deref())
            .map_err(|e| format!("device `{device_id}`: security.est.server: {e}"))?;
        // Auth: bootstrap and basic are mutually exclusive; a bootstrap identity must be complete.
        if let Some(auth) = &self.auth {
            if auth.bootstrap.is_some() && auth.basic.is_some() {
                return Err(format!(
                    "device `{device_id}`: security.est.auth sets BOTH bootstrap and basic — use one"
                ));
            }
            if let Some(b) = &auth.bootstrap {
                if !b.is_complete() {
                    return Err(format!(
                        "device `{device_id}`: security.est.auth.bootstrap needs a complete identity \
                         (certSecret, certFile+keyFile, or cert+key inline {{\"$secret\": …}})"
                    ));
                }
            }
        }
        // The write-back destination must be resolvable (explicit, or derivable from security.client).
        self.resolve_destination(sec).map_err(|e| format!("device `{device_id}`: {e}"))?;
        Ok(())
    }

    /// The renew threshold (days before `notAfter`): `est.renewBeforeDays`, else `client.renewBeforeDays`,
    /// else [`DEFAULT_RENEW_BEFORE_DAYS`].
    #[must_use]
    pub fn renew_before_days(&self, sec: &SecurityConfig) -> i64 {
        self.renew_before_days
            .map(i64::from)
            .or_else(|| sec.client.as_ref().and_then(|c| c.renew_before_days).map(i64::from))
            .unwrap_or(DEFAULT_RENEW_BEFORE_DAYS)
    }

    /// The retry backoff between failed attempts.
    #[must_use]
    pub fn retry_backoff(&self) -> Duration {
        Duration::from_secs(self.retry_backoff_mins.unwrap_or(DEFAULT_RETRY_BACKOFF_MINS) * 60)
    }

    /// The CSR subject CommonName.
    #[must_use]
    pub fn subject_cn(&self) -> &str {
        self.subject.as_deref().unwrap_or(DEFAULT_SUBJECT_CN)
    }

    /// Resolve the vault write-back destination: the explicit `into`, else derived from
    /// `security.client` (so the enrolled material lands where Phase 2b's watcher reads).
    ///
    /// # Errors
    ///
    /// A message when neither an explicit `into` nor a vault-backed client identity is available (e.g.
    /// a file-only client identity: EST cannot write a file, so an explicit `into` is required).
    pub fn resolve_destination(&self, sec: &SecurityConfig) -> Result<ResolvedDestination, String> {
        if let Some(into) = &self.into {
            return match (&into.cert_secret, &into.cert, &into.key) {
                (Some(b), None, None) => Ok(ResolvedDestination::Bundle(b.clone())),
                (None, Some(c), Some(k)) => {
                    Ok(ResolvedDestination::Pair { cert: c.clone(), key: k.clone() })
                }
                (None, None, None) => Err(
                    "security.est.into is empty — set certSecret (bundle) or cert+key (secret pair)"
                        .to_string(),
                ),
                _ => Err(
                    "security.est.into mixes styles — use certSecret (bundle) OR cert+key (secret pair)"
                        .to_string(),
                ),
            };
        }
        // Derive from the client identity.
        let client = sec.client.as_ref().ok_or_else(|| {
            "security.est needs a write-back destination — set est.into or a vault-backed \
             security.client (certSecret, or cert+key inline {\"$secret\": …})"
                .to_string()
        })?;
        if let Some(name) = &client.cert_secret {
            Ok(ResolvedDestination::Bundle(name.clone()))
        } else if let (Some(cert), Some(key)) = (&client.cert, &client.key) {
            Ok(ResolvedDestination::Pair {
                cert: cert.secret.clone(),
                key: key.secret.clone(),
            })
        } else {
            Err(
                "security.est cannot derive a write-back destination from a file-based \
                 security.client — set est.into (certSecret, or cert+key secrets)"
                    .to_string(),
            )
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------------------------------

/// A parsed EST server endpoint: the host, port (default 443), and the base path (`/.well-known/est`
/// plus any label). The per-operation paths are `<base>/{cacerts,simpleenroll,simplereenroll}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstEndpoint {
    /// The DNS name or IP literal.
    pub host: String,
    /// The TCP port (default 443).
    pub port: u16,
    /// The base path without a trailing slash, e.g. `/.well-known/est` or `/.well-known/est/eip`.
    pub base_path: String,
}

impl EstEndpoint {
    /// Parse an `https://host[:port]/path` URL, appending an optional EST `label` segment.
    ///
    /// # Errors
    ///
    /// A message when the scheme is not https, the host is empty, or the port is not a number.
    pub fn parse(url: &str, label: Option<&str>) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("`{url}` is not an https:// URL"))?;
        // Split authority from path at the first '/'.
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/.well-known/est"),
        };
        if authority.is_empty() {
            return Err(format!("`{url}` has no host"));
        }
        // host[:port] — leave a bracketed IPv6 literal intact.
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            // [ipv6]:port
            let end = stripped
                .find(']')
                .ok_or_else(|| format!("`{authority}` has an unterminated IPv6 literal"))?;
            let host = stripped[..end].to_string();
            let after = &stripped[end + 1..];
            let port = parse_optional_port(after.strip_prefix(':'))?;
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), parse_optional_port(Some(p))?)
                }
                _ => (authority.to_string(), 443),
            }
        };
        if host.is_empty() {
            return Err(format!("`{url}` has no host"));
        }
        let mut base_path = path.trim_end_matches('/').to_string();
        if base_path.is_empty() {
            base_path = "/.well-known/est".to_string();
        }
        if let Some(label) = label.filter(|l| !l.is_empty()) {
            base_path = format!("{base_path}/{}", label.trim_matches('/'));
        }
        Ok(Self { host, port, base_path })
    }

    /// The full request path for an EST operation (`cacerts` / `simpleenroll` / `simplereenroll`).
    #[must_use]
    pub fn op_path(&self, op: &str) -> String {
        format!("{}/{op}", self.base_path)
    }

    /// The `Host` header value (`host` or `host:port` when non-default).
    #[must_use]
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The rustls verification / SNI name (IP literal ⇒ `IpAddress`, else `DnsName`).
    ///
    /// # Errors
    ///
    /// A message when the host is not a valid DNS name or IP.
    pub fn server_name(&self) -> Result<ServerName<'static>, String> {
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            Ok(ServerName::IpAddress(ip.into()))
        } else {
            ServerName::try_from(self.host.clone())
                .map_err(|e| format!("invalid EST host `{}`: {e}", self.host))
        }
    }
}

fn parse_optional_port(p: Option<&str>) -> Result<u16, String> {
    match p {
        None => Ok(443),
        Some(s) => s.parse::<u16>().map_err(|_| format!("invalid port `{s}`")),
    }
}

// ---------------------------------------------------------------------------------------------------
// CSR generation
// ---------------------------------------------------------------------------------------------------

/// A freshly-generated enrollment keypair + its PKCS#10 CSR (DER).
pub struct CsrBundle {
    /// The private key, PKCS#8 PEM. Kept only until the enrolled cert is written to the vault.
    pub key_pem: String,
    /// The CSR, DER-encoded (base64 of this is the `application/pkcs10` request body).
    pub csr_der: Vec<u8>,
}

/// Generate a P-256 keypair and a PKCS#10 CSR with the given subject CommonName (`rcgen`, ring).
///
/// # Errors
///
/// A message when key generation or CSR serialization fails.
pub fn generate_key_and_csr(subject_cn: &str) -> Result<CsrBundle, String> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let mut params =
        CertificateParams::new(vec![]).map_err(|e| format!("CSR params: {e}"))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    let key = KeyPair::generate().map_err(|e| format!("generating the enrollment keypair: {e}"))?;
    let csr = params
        .serialize_request(&key)
        .map_err(|e| format!("serializing the CSR: {e}"))?;
    Ok(CsrBundle {
        key_pem: key.serialize_pem(),
        csr_der: csr.der().as_ref().to_vec(),
    })
}

// ---------------------------------------------------------------------------------------------------
// HTTP/1.1 request/response (pure)
// ---------------------------------------------------------------------------------------------------

/// The EST operation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstOp {
    /// `GET /cacerts` — fetch the CA cert bag for trust bootstrapping.
    CaCerts,
    /// `POST /simpleenroll` — initial enrollment of a new certificate.
    SimpleEnroll,
    /// `POST /simplereenroll` — renewal of the current certificate.
    SimpleReenroll,
}

impl EstOp {
    fn path_segment(self) -> &'static str {
        match self {
            EstOp::CaCerts => "cacerts",
            EstOp::SimpleEnroll => "simpleenroll",
            EstOp::SimpleReenroll => "simplereenroll",
        }
    }
    fn is_post(self) -> bool {
        !matches!(self, EstOp::CaCerts)
    }
}

/// Encode the HTTP/1.1 request bytes for an EST operation. For enroll operations the `csr_der` is
/// base64-encoded into an `application/pkcs10` body; `cacerts` is a bodyless GET. `basic_auth`, when
/// present, adds an `Authorization: Basic` header.
#[must_use]
pub fn encode_request(
    endpoint: &EstEndpoint,
    op: EstOp,
    csr_der: Option<&[u8]>,
    basic_auth: Option<(&str, &str)>,
) -> Vec<u8> {
    let path = endpoint.op_path(op.path_segment());
    let method = if op.is_post() { "POST" } else { "GET" };
    let body = csr_der.map(|der| base64::engine::general_purpose::STANDARD.encode(der));

    let mut req = String::new();
    req.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {}\r\n", endpoint.host_header()));
    req.push_str("User-Agent: edgecommons-ethernet-ip-adapter\r\n");
    req.push_str("Accept: application/pkcs7-mime\r\n");
    if let Some((user, pass)) = basic_auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Authorization: Basic {token}\r\n"));
    }
    if let Some(b) = &body {
        req.push_str("Content-Type: application/pkcs10\r\n");
        req.push_str("Content-Transfer-Encoding: base64\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("Connection: close\r\n");
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    if let Some(b) = body {
        out.extend_from_slice(b.as_bytes());
    }
    out
}

/// A parsed EST HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The numeric status code (e.g. 200, 202, 401).
    pub status: u16,
    /// `true` when a `Content-Transfer-Encoding: base64` header was present.
    pub base64_body: bool,
    /// The `Retry-After` header value in seconds, if present (for a 202).
    pub retry_after_secs: Option<u64>,
    /// The raw response body (still base64 text when `base64_body`).
    pub body: Vec<u8>,
}

/// Parse an HTTP/1.1 response (status line + headers + body). The body is taken as everything after the
/// header terminator (the caller reads to EOF under `Connection: close`).
///
/// # Errors
///
/// A message when the status line is malformed or the header block is unterminated.
pub fn parse_response(bytes: &[u8]) -> Result<HttpResponse, String> {
    // Find the header/body separator.
    let sep = find_subslice(bytes, b"\r\n\r\n")
        .ok_or_else(|| "malformed EST response: no header terminator".to_string())?;
    let head = std::str::from_utf8(&bytes[..sep])
        .map_err(|_| "malformed EST response: non-UTF-8 headers".to_string())?;
    let body = bytes[sep + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    // "HTTP/1.1 200 OK"
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("malformed EST status line: `{status_line}`"))?;

    let mut base64_body = false;
    let mut retry_after_secs = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            match name.as_str() {
                "content-transfer-encoding" if value.eq_ignore_ascii_case("base64") => {
                    base64_body = true;
                }
                "retry-after" => retry_after_secs = value.parse::<u64>().ok(),
                _ => {}
            }
        }
    }
    Ok(HttpResponse { status, base64_body, retry_after_secs, body })
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------------------------------
// PKCS#7 response parsing (pure)
// ---------------------------------------------------------------------------------------------------

/// Extract the DER certificates from an EST `application/pkcs7-mime` reply — a certs-only degenerate
/// PKCS#7 SignedData (RFC 7030 §4.2.3 / §4.1.3). The issued certificate is the leaf; a `/cacerts` bag
/// carries the CA chain.
///
/// # Errors
///
/// A message when the bytes are not a PKCS#7 SignedData or hold no certificates.
pub fn parse_pkcs7_certs(der: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    use cms::cert::CertificateChoices;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::{Decode, Encode};

    // id-signedData, 1.2.840.113549.1.7.2 (RFC 5652). Compared explicitly so no const-oid `db`
    // feature is needed.
    const ID_SIGNED_DATA: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
    let ci = ContentInfo::from_der(der)
        .map_err(|e| format!("parsing the PKCS#7 ContentInfo: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(format!(
            "EST reply is not PKCS#7 SignedData (content type {})",
            ci.content_type
        ));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| format!("parsing the PKCS#7 SignedData: {e}"))?;
    let set = sd
        .certificates
        .ok_or_else(|| "EST PKCS#7 reply carries no certificates".to_string())?;
    let mut out = Vec::new();
    for choice in set.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let bytes = cert
                .to_der()
                .map_err(|e| format!("re-encoding an issued certificate: {e}"))?;
            out.push(CertificateDer::from(bytes));
        }
    }
    if out.is_empty() {
        return Err("EST PKCS#7 reply held no X.509 certificates".to_string());
    }
    Ok(out)
}

/// Render a DER certificate chain as concatenated PEM (the `certPem` written to the vault).
#[must_use]
pub fn chain_to_pem(chain: &[CertificateDer<'static>]) -> String {
    let mut out = String::new();
    for cert in chain {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            // `chunks` never yields an out-of-range slice; UTF-8 base64 stays valid per 64-byte line.
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out
}

// ---------------------------------------------------------------------------------------------------
// Enrollment authentication material + write-back (adapter policy, testable)
// ---------------------------------------------------------------------------------------------------

/// The authentication material for one enrollment attempt, resolved from config + the vault.
#[derive(Debug, Clone)]
pub enum EstAuthMaterial {
    /// Mutual-TLS: present this client cert/key (a bootstrap identity, or the current cert for re-enroll).
    ClientCert { cert_pem: String, key_pem: String },
    /// HTTP Basic over TLS (optionally still presenting a client cert).
    Basic {
        username: String,
        password: String,
        client: Option<(String, String)>,
    },
}

/// Resolve the trust anchors (PEM) for verifying the EST server: `est.trust` if set, else the
/// connection's `security.ca`.
///
/// # Errors
///
/// A config-legible message from the vault/file sourcing.
pub fn resolve_est_trust(
    est: &EstConfig,
    sec: &SecurityConfig,
    creds: Option<&Arc<dyn CredentialService>>,
) -> Result<Vec<String>, String> {
    if let Some(trust) = &est.trust {
        source_ca_pems(trust, creds)
    } else if let Some(ca) = &sec.ca {
        source_ca_pems(ca, creds)
    } else {
        Err("security.est needs trust anchors for the EST server (est.trust or security.ca)".to_string())
    }
}

/// Resolve the authentication material for an enrollment attempt (DESIGN-cip-security.md §4.3):
/// Basic when configured, a bootstrap identity for the initial enroll, else the connection's current
/// client identity (mutual-TLS re-enroll).
///
/// # Errors
///
/// A config-legible message from the vault/file sourcing, or when no usable material is available.
pub fn resolve_auth_material(
    est: &EstConfig,
    sec: &SecurityConfig,
    creds: Option<&Arc<dyn CredentialService>>,
) -> Result<EstAuthMaterial, String> {
    // Current client identity from the connection (used for re-enroll and as the optional cert under Basic).
    let current = source_client_material(sec, creds).ok().and_then(|(c, k, _)| match (c, k) {
        (Some(c), Some(k)) => Some((c, k)),
        _ => None,
    });

    if let Some(auth) = &est.auth {
        if let Some(basic) = &auth.basic {
            let name = &basic.secret;
            let creds = creds.ok_or_else(|| {
                format!("security.est.auth.basic references `{name}` but no vault is configured")
            })?;
            let ba = creds
                .get_basic_auth(name)
                .map_err(|e| format!("vault get_basic_auth(`{name}`) for est.auth.basic: {e}"))?
                .ok_or_else(|| format!("vault secret `{name}` (est.auth.basic) not found"))?;
            return Ok(EstAuthMaterial::Basic {
                username: ba.username,
                password: ba.password,
                client: current,
            });
        }
        if let Some(bootstrap) = &auth.bootstrap {
            let (cert, key) = source_identity(bootstrap, creds)?;
            return Ok(EstAuthMaterial::ClientCert { cert_pem: cert, key_pem: key });
        }
    }
    // Default: reuse the connection's current client identity (mutual-TLS re-enroll).
    current
        .map(|(cert_pem, key_pem)| EstAuthMaterial::ClientCert { cert_pem, key_pem })
        .ok_or_else(|| {
            "security.est has no auth and no current client identity to re-enroll with — set \
             est.auth.bootstrap or est.auth.basic"
                .to_string()
        })
}

/// Source a [`ClientIdentity`]'s cert + key PEMs (bundle / files / inline), for the bootstrap identity.
fn source_identity(
    id: &ClientIdentity,
    creds: Option<&Arc<dyn CredentialService>>,
) -> Result<(String, String), String> {
    // Reuse the same sourcing as security.client by wrapping in a throwaway SecurityConfig.
    let sec = SecurityConfig::with_client(id.clone());
    match source_client_material(&sec, creds)? {
        (Some(c), Some(k), _) => Ok((c, k)),
        _ => Err("est.auth.bootstrap identity is incomplete".to_string()),
    }
}

/// Write the enrolled key+cert back into the vault at the resolved destination (a new secret version —
/// Phase 2b's watcher then detects the fingerprint change and reconnects). Returns the written secret
/// name(s) for logging.
///
/// # Errors
///
/// A message when the vault write fails or no vault is configured.
pub fn write_enrolled(
    dest: &ResolvedDestination,
    cert_pem: &str,
    key_pem: &str,
    creds: Option<&Arc<dyn CredentialService>>,
) -> Result<String, String> {
    use edgecommons::credentials::PutOptions;
    let creds = creds.ok_or_else(|| "security.est enrolled a cert but no vault is configured to store it".to_string())?;
    match dest {
        ResolvedDestination::Bundle(name) => {
            let bundle = serde_json::json!({ "certPem": cert_pem, "keyPem": key_pem });
            let bytes = serde_json::to_vec(&bundle).map_err(|e| format!("encoding the TLS bundle: {e}"))?;
            creds
                .put(name, &bytes, PutOptions::default())
                .map_err(|e| format!("vault put(`{name}`) for the enrolled bundle: {e}"))?;
            Ok(name.clone())
        }
        ResolvedDestination::Pair { cert, key } => {
            creds
                .put(cert, cert_pem.as_bytes(), PutOptions::default())
                .map_err(|e| format!("vault put(`{cert}`) for the enrolled cert: {e}"))?;
            creds
                .put(key, key_pem.as_bytes(), PutOptions::default())
                .map_err(|e| format!("vault put(`{key}`) for the enrolled key: {e}"))?;
            Ok(format!("{cert} + {key}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The async EST client (the socket-driving seam)
// ---------------------------------------------------------------------------------------------------

/// A thin RFC 7030 EST client over the Phase-1 rustls/ring TLS stack. Built per attempt from the
/// resolved endpoint, trust anchors, and auth material; performs one request and closes (the EST
/// server sets `Connection: close`).
pub struct EstClient {
    endpoint: EstEndpoint,
    tls: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    basic_auth: Option<(String, String)>,
    timeout: Duration,
}

impl EstClient {
    /// Build an EST client: verify the server against `trust_pems`, authenticate per `auth`, dial
    /// `endpoint`.
    ///
    /// # Errors
    ///
    /// A message for any PEM/trust/identity build failure.
    pub fn new(
        endpoint: EstEndpoint,
        trust_pems: &[String],
        auth: &EstAuthMaterial,
        timeout: Duration,
    ) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        // Trust store for the EST server.
        let mut roots = RootCertStore::empty();
        for pem in trust_pems {
            for cert in certs_from_pem(pem, "EST server CA")? {
                roots
                    .add(cert)
                    .map_err(|e| format!("adding an EST server CA to the trust store: {e}"))?;
            }
        }
        if roots.is_empty() {
            return Err("no EST server trust anchors were sourced (est.trust / security.ca)".to_string());
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("building the EST server verifier: {e}"))?;

        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("EST tls provider setup: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier);

        // Client authentication for the EST session.
        let (client_identity, basic_auth) = match auth {
            EstAuthMaterial::ClientCert { cert_pem, key_pem } => {
                (Some((cert_pem.clone(), key_pem.clone())), None)
            }
            EstAuthMaterial::Basic { username, password, client } => {
                (client.clone(), Some((username.clone(), password.clone())))
            }
        };
        let config = match client_identity {
            Some((cert_pem, key_pem)) => {
                let chain = certs_from_pem(&cert_pem, "EST client certificate")?;
                if chain.is_empty() {
                    return Err("EST client certificate PEM held no certificates".to_string());
                }
                let key = key_from_pem(&key_pem)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| format!("installing the EST client certificate/key: {e}"))?
            }
            None => builder.with_no_client_auth(),
        };

        let server_name = endpoint.server_name()?;
        Ok(Self {
            endpoint,
            tls: Arc::new(config),
            server_name,
            basic_auth,
            timeout,
        })
    }

    /// Perform one EST operation and return the parsed [`HttpResponse`]. TLS-connects, sends the
    /// request, reads to EOF (bounded by [`MAX_RESPONSE_BYTES`]), and parses.
    ///
    /// # Errors
    ///
    /// A message for a connect/handshake/IO failure or a malformed response.
    pub async fn request(&self, op: EstOp, csr_der: Option<&[u8]>) -> Result<HttpResponse, String> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let basic = self.basic_auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        let req = encode_request(&self.endpoint, op, csr_der, basic);

        let fut = async {
            let tcp = tokio::net::TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("connecting to EST server {addr}: {e}"))?;
            tcp.set_nodelay(true).ok();
            let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
            let mut tls = connector
                .connect(self.server_name.clone(), tcp)
                .await
                .map_err(|e| format!("EST TLS handshake to {addr} failed: {e}"))?;
            tls.write_all(&req)
                .await
                .map_err(|e| format!("sending the EST request: {e}"))?;
            tls.flush().await.ok();

            // Read the whole response (Connection: close ⇒ read to EOF), bounded.
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 8192];
            loop {
                let n = tls
                    .read(&mut chunk)
                    .await
                    .map_err(|e| format!("reading the EST response: {e}"))?;
                if n == 0 {
                    break;
                }
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(format!("EST response exceeds {MAX_RESPONSE_BYTES} bytes"));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok::<Vec<u8>, String>(buf)
        };

        let bytes = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| format!("EST request to {addr} timed out"))??;
        parse_response(&bytes)
    }

    /// Request a certificate (`simpleenroll` / `simplereenroll`): POST the CSR, decode the response,
    /// and extract the issued certificate chain. Surfaces a 202 as a typed "try later" and other
    /// non-200s with the status.
    ///
    /// # Errors
    ///
    /// [`EstError`] classifying the failure.
    pub async fn request_certificate(
        &self,
        reenroll: bool,
        csr_der: &[u8],
    ) -> Result<Vec<CertificateDer<'static>>, EstError> {
        let op = if reenroll { EstOp::SimpleReenroll } else { EstOp::SimpleEnroll };
        let resp = self.request(op, Some(csr_der)).await.map_err(EstError::Io)?;
        interpret_enroll_response(&resp)
    }

    /// Fetch the CA certificates (`/cacerts`) for trust bootstrapping.
    ///
    /// # Errors
    ///
    /// [`EstError`] classifying the failure.
    pub async fn cacerts(&self) -> Result<Vec<CertificateDer<'static>>, EstError> {
        let resp = self.request(EstOp::CaCerts, None).await.map_err(EstError::Io)?;
        if resp.status != 200 {
            return Err(EstError::Status(resp.status));
        }
        let der = decode_body(&resp)?;
        parse_pkcs7_certs(&der).map_err(EstError::Parse)
    }
}

/// Interpret an enroll response: 200 ⇒ parse the issued chain; 202 ⇒ retry-after; else a status error.
///
/// # Errors
///
/// [`EstError`] for a non-200 status or a parse failure.
pub fn interpret_enroll_response(resp: &HttpResponse) -> Result<Vec<CertificateDer<'static>>, EstError> {
    match resp.status {
        200 => {
            let der = decode_body(resp)?;
            parse_pkcs7_certs(&der).map_err(EstError::Parse)
        }
        202 => Err(EstError::RetryAfter(resp.retry_after_secs.unwrap_or(60))),
        401 | 403 => Err(EstError::Unauthorized(resp.status)),
        s => Err(EstError::Status(s)),
    }
}

/// Base64-decode a response body when it is marked base64 (EST always is), else return it as-is.
fn decode_body(resp: &HttpResponse) -> Result<Vec<u8>, EstError> {
    if resp.base64_body {
        // Tolerate embedded whitespace/newlines in the base64.
        let cleaned: Vec<u8> = resp
            .body
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(cleaned)
            .map_err(|e| EstError::Parse(format!("base64-decoding the EST reply: {e}")))
    } else {
        Ok(resp.body.clone())
    }
}

/// A typed EST failure.
#[derive(Debug, thiserror::Error)]
pub enum EstError {
    /// A socket/handshake/IO failure (transient — retry).
    #[error("EST transport: {0}")]
    Io(String),
    /// The server asked us to retry after N seconds (202 Accepted).
    #[error("EST enrollment pending — retry after {0}s")]
    RetryAfter(u64),
    /// The server rejected our authentication (401/403).
    #[error("EST authentication rejected (HTTP {0})")]
    Unauthorized(u16),
    /// An unexpected HTTP status.
    #[error("EST server returned HTTP {0}")]
    Status(u16),
    /// The response body could not be decoded/parsed.
    #[error("EST response: {0}")]
    Parse(String),
}

impl EstError {
    /// Whether retrying later might succeed (transport / pending / 5xx), vs a persistent
    /// misconfiguration (auth / parse / 4xx).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            EstError::Io(_) | EstError::RetryAfter(_) => true,
            EstError::Status(s) => *s >= 500,
            EstError::Unauthorized(_) | EstError::Parse(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The enrollment scheduler (pure decision) + status
// ---------------------------------------------------------------------------------------------------

/// One decision from [`EstScheduler`]: whether to attempt enrollment this tick, and which flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstDecision {
    /// Do nothing (cert healthy, or backing off after a recent failure).
    Idle,
    /// Enroll now. `reenroll` selects `simplereenroll` (a current valid cert exists) vs `simpleenroll`
    /// (initial — no cert, or the cert is unusable/expired).
    Enroll { reenroll: bool },
}

/// The pure enrollment-timing decision core (mirrors [`super::rotation::CertWatcher`]): given the
/// current client-cert expiry and the last-attempt bookkeeping, decide whether to enroll. The
/// supervisor drives it; all timing logic lives here and is unit-tested.
#[derive(Debug, Default)]
pub struct EstScheduler;

impl EstScheduler {
    /// Decide the action for this tick.
    ///
    /// * `current_expiry_days` — the vault client cert's days-to-expiry (`None` ⇒ no usable cert ⇒
    ///   initial enroll);
    /// * `renew_before_days` — renew when the cert is within this many days of expiry;
    /// * `since_last_attempt` — how long since the previous enrollment attempt (`None` ⇒ never);
    /// * `backoff` — minimum spacing between attempts.
    #[must_use]
    pub fn decide(
        current_expiry_days: Option<i64>,
        renew_before_days: i64,
        since_last_attempt: Option<Duration>,
        backoff: Duration,
    ) -> EstDecision {
        // Respect the retry backoff after any recent attempt.
        if let Some(elapsed) = since_last_attempt {
            if elapsed < backoff {
                return EstDecision::Idle;
            }
        }
        match current_expiry_days {
            // No usable cert ⇒ initial enroll.
            None => EstDecision::Enroll { reenroll: false },
            // Expired ⇒ initial enroll (the current cert can't authenticate a re-enroll).
            Some(days) if days < 0 => EstDecision::Enroll { reenroll: false },
            // Within the renew window ⇒ re-enroll with the current cert.
            Some(days) if days <= renew_before_days => EstDecision::Enroll { reenroll: true },
            // Healthy.
            Some(_) => EstDecision::Idle,
        }
    }
}

/// The EST lifecycle state surfaced on `sb/status.security.est` (DESIGN-cip-security.md §4.3). Shared
/// (behind a mutex in [`crate::app::Health`]) between the lifecycle driver, which updates it, and the
/// status view, which renders it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EstStatus {
    /// Whether EST enrollment is enabled for this instance.
    pub enabled: bool,
    /// The EST server URL (for the operator's reference).
    pub server: Option<String>,
    /// RFC-3339 timestamp of the last successful enrollment.
    pub last_enroll: Option<String>,
    /// RFC-3339 timestamp when the next renewal is expected (≈ `notAfter − renewBeforeDays`).
    pub next_renew: Option<String>,
    /// The last enrollment error message, if the most recent attempt failed.
    pub last_error: Option<String>,
    /// Successful enrollments so far (process lifetime).
    pub enrollments: u64,
    /// Failed enrollment attempts so far (process lifetime).
    pub failures: u64,
}

/// The result of a successful enrollment (for events + status).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollOutcome {
    /// The issued certificate's `notAfter`, RFC-3339.
    pub not_after: Option<String>,
    /// The issued certificate's serial, hex.
    pub serial: Option<String>,
    /// The vault secret name(s) the material was written to.
    pub written_to: String,
    /// The number of certificates in the issued chain.
    pub chain_len: usize,
}

/// Run one full enrollment: resolve material, generate a keypair+CSR, POST it to the EST server,
/// extract the issued certificate, and write the key+cert back into the vault (a new version — Phase
/// 2b's watcher then reconnects). `reenroll` selects `simplereenroll` vs `simpleenroll`.
///
/// This is the socket-driving orchestrator; the supervisor's `security_lifecycle` driver calls it.
///
/// # Errors
///
/// A message for any config, sourcing, transport, or vault-write failure.
pub async fn enroll_once(
    est: &EstConfig,
    sec: &SecurityConfig,
    creds: Option<&Arc<dyn CredentialService>>,
    reenroll: bool,
    connect_timeout: Duration,
) -> Result<EnrollOutcome, String> {
    let server = est
        .server
        .as_deref()
        .ok_or_else(|| "security.est.server is not set".to_string())?;
    let endpoint = EstEndpoint::parse(server, est.label.as_deref())?;
    let trust = resolve_est_trust(est, sec, creds)?;
    let auth = resolve_auth_material(est, sec, creds)?;
    let dest = est.resolve_destination(sec)?;

    let csr = generate_key_and_csr(est.subject_cn())?;
    let client = EstClient::new(endpoint, &trust, &auth, connect_timeout)?;

    // Optional trust bootstrap: confirm the EST server's CA bag before enrolling (RFC 7030 §4.1).
    if est.fetch_ca_certs {
        match client.cacerts().await {
            Ok(bag) => tracing::info!(count = bag.len(), "EST /cacerts fetched (trust bootstrap)"),
            Err(e) => tracing::warn!(error = %e, transient = e.is_transient(), "EST /cacerts failed (continuing with configured trust)"),
        }
    }

    let chain = client
        .request_certificate(reenroll, &csr.csr_der)
        .await
        .map_err(|e| {
            let hint = if e.is_transient() { " (transient — will retry)" } else { "" };
            format!("{e}{hint}")
        })?;

    let cert_pem = chain_to_pem(&chain);
    let (not_after, serial) = match chain.first() {
        Some(leaf) => (
            super::tls::cert_not_after(leaf.as_ref()),
            super::tls::cert_serial(leaf.as_ref()),
        ),
        None => (None, None),
    };
    let written_to = write_enrolled(&dest, &cert_pem, &csr.key_pem, creds)?;
    Ok(EnrollOutcome {
        not_after,
        serial,
        written_to,
        chain_len: chain.len(),
    })
}

/// Compute the expected next-renewal timestamp (RFC-3339) from a certificate's `notAfter` and the
/// renew-before window: `notAfter − renewBeforeDays`.
#[must_use]
pub fn next_renew_rfc3339(not_after: Option<&str>, renew_before_days: i64) -> Option<String> {
    let na = not_after?;
    let parsed = time::OffsetDateTime::parse(na, &time::format_description::well_known::Rfc3339).ok()?;
    let renew_at = parsed - time::Duration::days(renew_before_days);
    renew_at
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

impl EstStatus {
    /// Render to the `sb/status.security.est` JSON object.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "server": self.server,
            "lastEnroll": self.last_enroll,
            "nextRenew": self.next_renew,
            "lastError": self.last_error,
            "enrollments": self.enrollments,
            "failures": self.failures,
        })
    }
}

#[cfg(test)]
mod tests;
