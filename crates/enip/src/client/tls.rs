//! TLS transport for the explicit-messaging session — CIP Security Phase 1 (feature `tls`).
//!
//! ODVA Volume 8 ("CIP Security") wraps the **unchanged** EtherNet/IP encapsulation session in
//! TLS 1.2+/1.3 on TCP **2221** ([`crate::encap::DEFAULT_TLS_PORT`]). TLS sits *below* the
//! encapsulation codec and *above* TCP, so the entire session machinery — framing, correlation,
//! deadlines, stale-reply quarantine, class-3 sequencing — runs over TLS **unchanged**: a
//! [`tokio_rustls::client::TlsStream`] satisfies `AsyncRead + AsyncWrite + Unpin + Send`, exactly
//! the bound [`EipClient::connect_over`](crate::EipClient::connect_over) already requires
//! (PROTOCOL-DESIGN §11.1 / DESIGN-cip-security.md §3.1).
//!
//! ## The isolation contract is preserved
//!
//! This module knows TLS-the-protocol (Vol 8 *is* EtherNet/IP) but **nothing** about EdgeCommons or
//! about where certificates come from. The caller (the adapter) builds a
//! [`rustls::ClientConfig`] — parsing PEM, choosing the trust anchors, the client identity, the
//! verifier, the suite constraints — and hands it in as an opaque [`TlsOptions`]. The crate never
//! reads a vault, a file, or a key byte's provenance.
//!
//! ## Cipher suites
//!
//! `rustls` is AEAD-only: it speaks the GCM suites Vol 8 ≥ 1.13 mandates (e.g.
//! `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, 0xC02B) natively, plus the TLS 1.3 suites. It does
//! **not** speak the legacy CBC/NULL/PSK suites 2019–2021-era firmware may offer — that is the
//! documented interop boundary (§2.4), surfaced as the typed [`TlsErrorKind::NoCipherOverlap`].

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use rustls::pki_types::ServerName;

use crate::error::{EnipError, Result, TlsErrorKind};

use super::{ClientOptions, EipClient};

/// The prepared TLS parameters for [`EipClient::connect_tls`] — built by the **caller**, never by
/// this crate. `config` carries the trust anchors, the client identity (mutual TLS), the certificate
/// verifier, and any cipher-suite constraint; `server_name` is the verification/SNI identity, which
/// for a PLC dialed by IP is a [`ServerName::IpAddress`] verified against the device certificate's IP
/// SAN (DESIGN-cip-security.md §3.1).
#[derive(Clone)]
pub struct TlsOptions {
    /// The fully-built rustls client configuration (opaque to this crate).
    pub config: Arc<rustls::ClientConfig>,
    /// The verification / SNI name — typically `ServerName::IpAddress(<endpoint ip>)`.
    pub server_name: ServerName<'static>,
}

impl std::fmt::Debug for TlsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the ClientConfig (it holds key material); just the peer name.
        f.debug_struct("TlsOptions")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// The negotiated TLS session facts, captured at handshake time for the adapter's `sb/status`
/// security surface (DESIGN-cip-security.md §3.4). Read via [`EipClient::tls_session_info`].
///
/// The crate reports what it observed on the wire (version, suite, whether the peer presented a
/// certificate + its leaf DER); it does **not** decide "verified" — that is the caller's policy
/// (whether it built a verifying or a no-verify `ClientConfig`).
#[derive(Debug, Clone, Default)]
pub struct TlsSessionInfo {
    /// The negotiated protocol version, rendered as `"1.3"` / `"1.2"` (`None` if unavailable).
    pub protocol_version: Option<String>,
    /// The negotiated cipher suite, e.g. `"TLS13_AES_128_GCM_SHA256"` (`None` if unavailable).
    pub cipher_suite: Option<String>,
    /// The peer (device) leaf certificate in DER, when the peer presented a chain — lets the adapter
    /// render the peer identity / expiry. `None` when the peer sent no certificate.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl EipClient {
    /// Connect to `addr` over **TLS** and open a session (CIP Security explicit path,
    /// DESIGN-cip-security.md §3.1): a bounded TCP connect to the target (default port
    /// [`crate::encap::DEFAULT_TLS_PORT`] `2221` unless `opts.port`/`addr` says otherwise), a rustls
    /// handshake, then the existing RegisterSession + session actor — the whole explicit surface
    /// rides inside TLS unchanged.
    ///
    /// # Errors
    ///
    /// [`EnipError::Timeout`] if the connect/handshake exceeds `opts.connect_timeout`;
    /// [`EnipError::Tls`] (classified [`TlsErrorKind`]) for a socket, handshake, verification, or
    /// no-cipher-overlap failure; the ordinary RegisterSession errors thereafter.
    pub async fn connect_tls(addr: &str, opts: ClientOptions, tls: TlsOptions) -> Result<Self> {
        let target = if addr.contains(':') {
            addr.to_owned()
        } else {
            format!("{addr}:{}", opts.port)
        };
        let started = std::time::Instant::now();
        let connect = TcpStream::connect(&target);
        let tcp = match tokio::time::timeout(opts.connect_timeout, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(EnipError::Tls {
                    kind: TlsErrorKind::Io,
                    detail: e.to_string(),
                })
            }
            Err(_elapsed) => return Err(EnipError::Timeout { op: "connect" }),
        };
        tcp.set_nodelay(true).ok();
        let peer_addr = tcp.peer_addr().ok();
        // The handshake shares the connect budget (§3.1: handshake inside connect_timeout).
        let remaining = opts
            .connect_timeout
            .saturating_sub(started.elapsed())
            .max(Duration::from_millis(1));
        let mut client = tokio::time::timeout(remaining, Self::connect_tls_over(tcp, opts, tls))
            .await
            .map_err(|_elapsed| EnipError::Timeout { op: "tls handshake" })??;
        client.peer_addr = peer_addr;
        Ok(client)
    }

    /// Perform the rustls client handshake over an already-connected byte stream, then register the
    /// session (the stream-injection entry point for TLS, mirroring
    /// [`EipClient::connect_over`](crate::EipClient::connect_over)). Production goes through
    /// [`EipClient::connect_tls`]; the unit tests pass a [`tokio::io::duplex`] half with a rustls
    /// **server** on the other end (a TLS endpoint on a byte pipe — not an embedded EtherNet/IP peer,
    /// D-ENIP-14 preserved).
    ///
    /// # Errors
    ///
    /// [`EnipError::Tls`] for a handshake/verification/no-overlap failure, then the ordinary
    /// RegisterSession errors.
    pub async fn connect_tls_over<S>(stream: S, opts: ClientOptions, tls: TlsOptions) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = tokio_rustls::TlsConnector::from(tls.config);
        let tls_stream = connector
            .connect(tls.server_name, stream)
            .await
            .map_err(map_handshake_error)?;
        let info = session_info(&tls_stream);
        let mut client = Self::connect_over(tls_stream, opts).await?;
        client.tls_info = Some(info);
        Ok(client)
    }

    /// The negotiated TLS session facts (version, suite, peer leaf cert), or `None` for a plaintext
    /// client. Consumed by the adapter's `sb/status` security surface (DESIGN-cip-security.md §3.4).
    #[must_use]
    pub fn tls_session_info(&self) -> Option<&TlsSessionInfo> {
        self.tls_info.as_ref()
    }
}

/// Capture the negotiated session facts from a freshly-handshaked client stream.
fn session_info<S>(stream: &tokio_rustls::client::TlsStream<S>) -> TlsSessionInfo {
    let (_io, conn) = stream.get_ref();
    TlsSessionInfo {
        protocol_version: conn.protocol_version().map(fmt_version),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite())),
        peer_cert_der: conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|c| c.as_ref().to_vec()),
    }
}

/// Render a rustls protocol version as the short `"1.3"` / `"1.2"` form (falling back to the debug
/// name for anything else).
fn fmt_version(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "1.2".to_string(),
        other => format!("{other:?}"),
    }
}

/// Map a tokio-rustls handshake `io::Error` to the typed [`EnipError::Tls`]. tokio-rustls surfaces
/// rustls handshake failures as an `io::Error` wrapping a [`rustls::Error`]; a cert-verification
/// failure becomes [`TlsErrorKind::PeerUnverified`], a no-suites/handshake-failure-alert becomes the
/// dedicated [`TlsErrorKind::NoCipherOverlap`] (the pre-1.13 CBC-only device case, §3.1), and a plain
/// socket error becomes [`TlsErrorKind::Io`].
fn map_handshake_error(e: std::io::Error) -> EnipError {
    if let Some(inner) = e.get_ref() {
        if let Some(rustls_err) = inner.downcast_ref::<rustls::Error>() {
            return classify_rustls_error(rustls_err);
        }
    }
    EnipError::Tls {
        kind: TlsErrorKind::Io,
        detail: e.to_string(),
    }
}

/// The no-cipher-overlap remediation text the spec-current-vs-legacy boundary demands (§3.1): it
/// must name the likely cause so an operator does not chase a phantom.
const NO_OVERLAP_HINT: &str =
    "no common cipher suite — target may be pre-1.13 CIP Security (CBC-only); enable GCM suites on \
     the device or see docs";

/// Classify a [`rustls::Error`] into a [`TlsErrorKind`] + detail string (exposed for unit testing;
/// see the tests in this module).
pub(crate) fn classify_rustls_error(err: &rustls::Error) -> EnipError {
    use rustls::{AlertDescription, Error, PeerIncompatible};
    let kind = match err {
        Error::InvalidCertificate(_) => TlsErrorKind::PeerUnverified,
        Error::PeerIncompatible(
            PeerIncompatible::NoCipherSuitesInCommon
            | PeerIncompatible::NoSignatureSchemesInCommon
            | PeerIncompatible::NoKxGroupsInCommon,
        ) => TlsErrorKind::NoCipherOverlap,
        // A CBC-only server rejects our GCM-only ClientHello with a handshake_failure alert.
        Error::AlertReceived(AlertDescription::HandshakeFailure) => TlsErrorKind::NoCipherOverlap,
        _ => TlsErrorKind::HandshakeFailed,
    };
    let detail = if kind == TlsErrorKind::NoCipherOverlap {
        format!("{NO_OVERLAP_HINT} ({err})")
    } else {
        err.to_string()
    };
    EnipError::Tls { kind, detail }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::net::{IpAddr, Ipv4Addr};

    // ---- pure error-mapping tests (no socket) ----

    #[test]
    fn invalid_cert_maps_to_peer_unverified() {
        let e = classify_rustls_error(&rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        match e {
            EnipError::Tls { kind, .. } => assert_eq!(kind, TlsErrorKind::PeerUnverified),
            other => panic!("expected Tls, got {other:?}"),
        }
    }

    #[test]
    fn expired_cert_maps_to_peer_unverified() {
        let e = classify_rustls_error(&rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
        assert!(matches!(
            e,
            EnipError::Tls { kind: TlsErrorKind::PeerUnverified, .. }
        ));
    }

    #[test]
    fn no_suites_in_common_maps_to_no_cipher_overlap_with_hint() {
        let e = classify_rustls_error(&rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::NoCipherSuitesInCommon,
        ));
        match e {
            EnipError::Tls { kind, detail } => {
                assert_eq!(kind, TlsErrorKind::NoCipherOverlap);
                assert!(detail.contains("CBC-only"), "must carry the legacy hint: {detail}");
                assert!(!kind.is_transient(), "cert/suite failures are non-transient");
            }
            other => panic!("expected Tls, got {other:?}"),
        }
    }

    #[test]
    fn handshake_failure_alert_maps_to_no_cipher_overlap() {
        let e = classify_rustls_error(&rustls::Error::AlertReceived(
            rustls::AlertDescription::HandshakeFailure,
        ));
        assert!(matches!(
            e,
            EnipError::Tls { kind: TlsErrorKind::NoCipherOverlap, .. }
        ));
    }

    #[test]
    fn other_rustls_error_maps_to_handshake_failed() {
        let e = classify_rustls_error(&rustls::Error::DecryptError);
        assert!(matches!(
            e,
            EnipError::Tls { kind: TlsErrorKind::HandshakeFailed, .. }
        ));
    }

    #[test]
    fn plain_io_error_maps_to_transient_io() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let e = map_handshake_error(io);
        match e {
            EnipError::Tls { kind, .. } => {
                assert_eq!(kind, TlsErrorKind::Io);
                assert!(kind.is_transient(), "pre-handshake io is transient");
                assert!(EnipError::Tls { kind, detail: String::new() }.is_transient());
            }
            other => panic!("expected Tls, got {other:?}"),
        }
    }

    #[test]
    fn wrapped_rustls_error_in_io_is_unwrapped() {
        // tokio-rustls wraps handshake failures in an io::Error; the mapper must reach inside.
        let inner = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
        assert!(matches!(
            map_handshake_error(io),
            EnipError::Tls { kind: TlsErrorKind::PeerUnverified, .. }
        ));
    }

    #[test]
    fn fmt_version_renders_short_names() {
        assert_eq!(fmt_version(rustls::ProtocolVersion::TLSv1_3), "1.3");
        assert_eq!(fmt_version(rustls::ProtocolVersion::TLSv1_2), "1.2");
    }

    #[test]
    fn tls_options_debug_hides_config() {
        let (server_cfg, _ca) = test_server_config(true);
        let _ = server_cfg;
        // A trivial ClientConfig for the Debug check (ring provider — see `ring()`).
        let roots = rustls::RootCertStore::empty();
        let cfg = rustls::ClientConfig::builder_with_provider(ring())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let opts = TlsOptions {
            config: Arc::new(cfg),
            server_name: ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        };
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("server_name"));
        assert!(!dbg.contains("ClientConfig"), "config must not be rendered");
    }

    // ---- handshake-over-duplex tests (rustls server on a byte pipe; §3.5) ----

    /// A tiny CA + leaf-cert fixture minted in-memory with rcgen (throwaway; never checked in).
    struct CertFixture {
        ca_der: CertificateDer<'static>,
        server_chain: Vec<CertificateDer<'static>>,
        server_key: PrivateKeyDer<'static>,
        client_chain: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
    }

    fn mint() -> CertFixture {
        use rcgen::{
            BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType,
        };
        // Self-signed CA.
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Server leaf with an IP SAN for 127.0.0.1 (PLCs are dialed by IP).
        let mut sp = CertificateParams::new(vec![]).unwrap();
        sp.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = sp.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // Client leaf (mutual TLS).
        let cp = CertificateParams::new(vec!["eip-originator".to_string()]).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = cp.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        CertFixture {
            ca_der: ca_cert.der().clone(),
            server_chain: vec![server_cert.der().clone()],
            server_key: PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
            client_chain: vec![client_cert.der().clone()],
            client_key: PrivateKeyDer::try_from(client_key.serialize_der()).unwrap(),
        }
    }

    /// A rustls server config that (optionally) requires and verifies a client cert against the CA.
    fn test_server_config(_require_client: bool) -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
        let fx = mint();
        let cfg = server_config_from(&fx, true);
        (cfg, fx.ca_der)
    }

    // The workspace can compile both the ring and aws-lc-rs rustls providers, so the process-default
    // provider is ambiguous — select ring explicitly in every test builder.
    fn ring() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn server_config_from(fx: &CertFixture, require_client: bool) -> Arc<rustls::ServerConfig> {
        let builder = rustls::ServerConfig::builder_with_provider(ring())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = if require_client {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(fx.ca_der.clone()).unwrap();
            let verifier =
                rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), ring())
                    .build()
                    .unwrap();
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        Arc::new(
            builder
                .with_single_cert(fx.server_chain.clone(), fx.server_key.clone_key())
                .unwrap(),
        )
    }

    fn client_config(fx: &CertFixture, present_client_cert: bool) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(fx.ca_der.clone()).unwrap();
        let builder = rustls::ClientConfig::builder_with_provider(ring())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);
        let cfg = if present_client_cert {
            builder
                .with_client_auth_cert(fx.client_chain.clone(), fx.client_key.clone_key())
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        Arc::new(cfg)
    }

    fn localhost_name() -> ServerName<'static> {
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into())
    }

    /// Drive a full mutual-TLS handshake over a duplex byte pipe and send one RegisterSession — the
    /// server side is a rustls acceptor that answers RegisterSession, proving the whole session
    /// machinery rides inside TLS. This is the crate-tier crypto-vs-crypto check; independent-
    /// implementation interop comes from the live stunnel target (`tests/live_tls.rs`).
    #[tokio::test]
    async fn mutual_tls_handshake_then_register_session() {
        let fx = mint();
        let server_cfg = server_config_from(&fx, true);
        let client_cfg = client_config(&fx, true);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        // Server: accept TLS, then answer a single RegisterSession request.
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let mut tls = acceptor.accept(server_io).await.expect("server handshake");
            answer_register_session(&mut tls).await;
        });

        let opts = ClientOptions {
            connect_timeout: Duration::from_secs(5),
            ..Default::default()
        };
        let tls = TlsOptions {
            config: client_cfg,
            server_name: localhost_name(),
        };
        let client = EipClient::connect_tls_over(client_io, opts, tls)
            .await
            .expect("client connect_tls_over");

        // The negotiated session facts are captured.
        let info = client.tls_session_info().expect("tls info present");
        assert!(info.protocol_version.is_some());
        assert!(info.cipher_suite.is_some());
        assert!(info.peer_cert_der.is_some(), "server presented a cert");
        client.close().await;
        server.await.unwrap();
    }

    /// A wrong CA on the client side ⇒ the device cert does not verify ⇒ typed `PeerUnverified`.
    #[tokio::test]
    async fn wrong_ca_is_rejected_as_peer_unverified() {
        let server_fx = mint();
        let other_fx = mint(); // a different CA the client will (wrongly) trust
        let server_cfg = server_config_from(&server_fx, false);
        let client_cfg = client_config(&other_fx, false);

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let _ = acceptor.accept(server_io).await; // will fail; ignore
        });

        let opts = ClientOptions::default();
        let tls = TlsOptions {
            config: client_cfg,
            server_name: localhost_name(),
        };
        let err = match EipClient::connect_tls_over(client_io, opts, tls).await {
            Ok(_) => panic!("wrong CA must fail"),
            Err(e) => e,
        };
        assert!(
            matches!(err, EnipError::Tls { kind: TlsErrorKind::PeerUnverified, .. }),
            "got {err:?}"
        );
        let _ = server.await;
    }

    /// The server requires a client cert; the client presents none ⇒ the connection fails
    /// (mutual-TLS enforcement). In TLS 1.3 the server's `certificate_required` alert arrives after
    /// the client believes the handshake done, so it surfaces during RegisterSession as a connection
    /// error rather than a handshake error — either way the connect fails loudly, which is the
    /// contract (no silent plaintext downgrade).
    #[tokio::test]
    async fn missing_client_cert_is_rejected() {
        let fx = mint();
        let server_cfg = server_config_from(&fx, true); // requires a client cert
        let client_cfg = client_config(&fx, false); // presents none

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
            let _ = acceptor.accept(server_io).await;
        });

        let opts = ClientOptions::default();
        let tls = TlsOptions {
            config: client_cfg,
            server_name: localhost_name(),
        };
        let err = match EipClient::connect_tls_over(client_io, opts, tls).await {
            Ok(_) => panic!("missing client cert must fail"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                EnipError::Tls { .. } | EnipError::Io(_) | EnipError::ConnectionLost { .. }
            ),
            "got {err:?}"
        );
        let _ = server.await;
    }

    /// Read one RegisterSession request off the TLS stream and write a well-formed reply, so the
    /// client's `connect_over` handshake completes. Minimal — just enough to prove the framing rides
    /// inside TLS.
    async fn answer_register_session<S>(tls: &mut S)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Read the 24-byte header + 4-byte body of RegisterSession.
        let mut hdr = [0u8; 24];
        if tls.read_exact(&mut hdr).await.is_err() {
            return;
        }
        let data_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
        let mut body = vec![0u8; data_len];
        if tls.read_exact(&mut body).await.is_err() {
            return;
        }
        // Build a RegisterSession reply: command 0x0065, len 4, a non-zero session handle, status 0,
        // echo the sender context, protocol version 1 + options 0.
        let mut reply = Vec::with_capacity(28);
        reply.extend_from_slice(&0x0065u16.to_le_bytes()); // command
        reply.extend_from_slice(&4u16.to_le_bytes()); // length
        reply.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // session handle
        reply.extend_from_slice(&0u32.to_le_bytes()); // status ok
        reply.extend_from_slice(&hdr[12..20]); // echo sender context
        reply.extend_from_slice(&0u32.to_le_bytes()); // options
        reply.extend_from_slice(&1u16.to_le_bytes()); // protocol version
        reply.extend_from_slice(&0u16.to_le_bytes()); // options
        let _ = tls.write_all(&reply).await;
        let _ = tls.flush().await;
        // Drain until the client closes (it will send UnRegisterSession on close()).
        let mut sink = [0u8; 64];
        loop {
            match tls.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}
