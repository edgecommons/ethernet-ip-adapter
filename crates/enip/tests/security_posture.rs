//! CIP Security posture-read state-machine tests (DESIGN-cip-security.md §4.1, PROTOCOL-DESIGN §7.7).
//!
//! Drives [`EipClient::read_security_posture`] over an in-memory [`tokio::io::duplex`] byte pipe with
//! a mock peer that answers `Get_Attribute_Single` (0x0E) for the 0x5D/0x5E/0x5F objects — proving the
//! typed decoders assemble the real posture, and that a device which refuses the objects (CIP status
//! 0x08) reports `unavailable`, never an error. No socket, no PLC (the §12.2 duplex-fixture pattern).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use enip::{
    CipSecurityState, ClientOptions, Cpf, CpfItem, EipClient, EncapFrame, EncapHeader, WireReader,
    WireWriter,
};
use enip::encap::Command;

const SESSION_HANDLE: u32 = 0x00AB_CDEF;

struct MockPeer {
    stream: DuplexStream,
    buf: BytesMut,
}

impl MockPeer {
    fn new(stream: DuplexStream) -> Self {
        Self { stream, buf: BytesMut::new() }
    }
    async fn recv(&mut self) -> Option<EncapFrame> {
        loop {
            if self.buf.len() >= 24 {
                let header = EncapHeader::decode(&self.buf[..24]).unwrap();
                let total = 24 + header.length as usize;
                if self.buf.len() >= total {
                    let frame_bytes = self.buf.split_to(total);
                    return Some(EncapFrame::decode(&frame_bytes).unwrap());
                }
            }
            let n = self.stream.read_buf(&mut self.buf).await.unwrap();
            if n == 0 {
                return None;
            }
        }
    }
    async fn send(&mut self, frame: &EncapFrame) {
        let bytes = frame.encode().unwrap();
        self.stream.write_all(&bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }
    async fn handle_register(&mut self) {
        let req = self.recv().await.expect("register");
        assert_eq!(req.header.command, Command::RegisterSession);
        let reply = EncapFrame::new(
            EncapHeader::request(Command::RegisterSession, 0, SESSION_HANDLE, req.header.sender_context),
            Bytes::from(vec![0x01, 0x00, 0x00, 0x00]),
        );
        self.send(&reply).await;
    }
}

fn mr_reply(service: u8, status: u8, data: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.u8(service | 0x80);
    w.u8(0);
    w.u8(status);
    w.u8(0);
    w.put_slice(data);
    w.into_bytes().to_vec()
}

fn rrdata_reply(ctx: [u8; 8], mr: &[u8]) -> EncapFrame {
    let cpf = Cpf::from_items(vec![
        CpfItem::null_address(),
        CpfItem::unconnected_data(Bytes::copy_from_slice(mr)),
    ]);
    let cpf_bytes = cpf.encode().unwrap();
    let mut w = WireWriter::new();
    w.u32(0);
    w.u16(0);
    w.put_slice(&cpf_bytes);
    EncapFrame::new(
        EncapHeader::request(Command::SendRRData, 0, SESSION_HANDLE, ctx),
        Bytes::from(w.into_bytes().to_vec()),
    )
}

/// Parse a `Get_Attribute_Single` UCMM request into `(class, instance, attribute)` by walking the
/// padded logical EPATH segments (8-bit and 16-bit forms).
fn parse_get_attr(frame: &EncapFrame) -> (u8, u16, u16, u16) {
    let mut r = WireReader::new(&frame.data);
    r.u32().unwrap(); // interface handle
    r.u16().unwrap(); // timeout
    let cpf = Cpf::decode(r.take_rest()).unwrap();
    let mr = cpf.expect_explicit_data().unwrap();
    let mut mr_r = WireReader::new(mr);
    let service = mr_r.u8().unwrap();
    let path_words = mr_r.u8().unwrap() as usize;
    let path = mr_r.take(path_words * 2).unwrap();
    let mut pr = WireReader::new(path);
    let (mut class, mut instance, mut attr) = (0u16, 0u16, 0u16);
    while !pr.is_empty() {
        let seg = pr.u8().unwrap();
        match seg {
            0x20 => class = u16::from(pr.u8().unwrap()),
            0x21 => {
                pr.u8().unwrap(); // pad
                class = pr.u16().unwrap();
            }
            0x24 => instance = u16::from(pr.u8().unwrap()),
            0x25 => {
                pr.u8().unwrap();
                instance = pr.u16().unwrap();
            }
            0x30 => attr = u16::from(pr.u8().unwrap()),
            0x31 => {
                pr.u8().unwrap();
                attr = pr.u16().unwrap();
            }
            _ => break,
        }
    }
    (service, class, instance, attr)
}

/// A mock CIP-Security-capable device: answers every 0x5D/0x5E/0x5F attribute with a crafted value.
fn answer_full(class: u16, instance: u16, attr: u16) -> (u8, Vec<u8>) {
    match (class, instance, attr) {
        (0x5D, 1, 1) => (0x00, vec![0x02]),             // Configured
        (0x5D, 1, 2) => (0x00, vec![0x03, 0x00]),       // profiles supported: Integrity+Confidentiality
        (0x5D, 1, 3) => (0x00, vec![0x02, 0x00]),       // profiles configured: Confidentiality
        (0x5E, 1, 1) => (0x00, vec![0x02]),             // state
        (0x5E, 1, 2) => (0x00, vec![0x00, 0x00, 0x00, 0x00]), // capability flags
        (0x5E, 1, 3) => (0x00, vec![0x02, 0xC0, 0x2B, 0xC0, 0x23]), // available: GCM + CBC
        (0x5E, 1, 4) => (0x00, vec![0x01, 0xC0, 0x2B]), // allowed: GCM only
        (0x5E, 1, 9) => (0x00, vec![0x01]),             // verify client true
        (0x5E, 1, 10) => (0x00, vec![0x01]),            // send chain true
        (0x5E, 1, 11) => (0x00, vec![0x00]),            // check expiration false
        (0x5F, 0, 8) => (0x00, vec![0x01, 0x00, 0x00, 0x00]), // push supported
        (0x5F, 1, 1) => (0x00, {
            let mut v = vec![0x06];
            v.extend_from_slice(b"Device");
            v
        }),
        (0x5F, 1, 2) => (0x00, vec![0x03]), // Verified
        (0x5F, 1, 5) => (0x00, vec![0x00]), // PEM
        _ => (0x14, Vec::new()),            // attribute not supported
    }
}

#[tokio::test]
async fn reads_full_security_posture_from_a_cip_security_device() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        while let Some(req) = peer.recv().await {
            if req.header.command != Command::SendRRData {
                break;
            }
            let (svc, class, instance, attr) = parse_get_attr(&req);
            assert_eq!(svc, 0x0E, "get_attribute_single");
            let (status, data) = answer_full(class, instance, attr);
            peer.send(&rrdata_reply(req.header.sender_context, &mr_reply(0x0E, status, &data)))
                .await;
        }
    });

    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_millis(500),
        ..ClientOptions::default()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let posture = client.read_security_posture().await.unwrap();
    assert!(posture.is_available(), "device implements CIP Security");

    let cip = posture.cip_security.expect("0x5D present");
    assert_eq!(cip.state, CipSecurityState::Configured);
    let supported = cip.profiles_supported.expect("profiles supported");
    assert!(supported.names().contains(&"EtherNet/IP Confidentiality"));
    assert!(supported.names().contains(&"EtherNet/IP Integrity"));

    let eip = posture.eip_security.expect("0x5E present");
    assert_eq!(eip.verify_client_certificate, Some(true));
    assert_eq!(eip.check_expiration, Some(false));
    let allowed = eip.allowed_cipher_suites.expect("allowed suites");
    assert_eq!(
        allowed.labels(),
        vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string()]
    );
    let available = eip.available_cipher_suites.expect("available suites");
    assert_eq!(available.suites.len(), 2);

    let cert = posture.certificate_management.expect("0x5F present");
    let caps = cert.capabilities.expect("caps");
    assert!(caps.push_supported());
    assert!(!caps.pull_supported());
    let inst = cert.instance1.expect("cert instance 1");
    assert_eq!(inst.name.as_deref(), Some("Device"));

    client.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn generic_device_reports_unavailable_not_error() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut peer = MockPeer::new(server_io);
        peer.handle_register().await;
        while let Some(req) = peer.recv().await {
            if req.header.command != Command::SendRRData {
                break;
            }
            let (svc, _c, _i, _a) = parse_get_attr(&req);
            assert_eq!(svc, 0x0E);
            // Service not supported / object does not exist — the generic-CIP-device answer.
            peer.send(&rrdata_reply(req.header.sender_context, &mr_reply(0x0E, 0x08, &[])))
                .await;
        }
    });

    let opts = ClientOptions {
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_millis(500),
        ..ClientOptions::default()
    };
    let client = EipClient::connect_over(client_io, opts).await.unwrap();
    let posture = client.read_security_posture().await.expect("no error on unavailable");
    assert!(!posture.is_available(), "no CIP Security objects ⇒ unavailable");
    assert!(posture.cip_security.is_none());
    assert!(posture.eip_security.is_none());
    assert!(posture.certificate_management.is_none());
    client.close().await;
    server.await.unwrap();
}
