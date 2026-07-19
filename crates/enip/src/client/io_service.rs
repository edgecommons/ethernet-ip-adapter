//! The class-1 I/O session seam (PROTOCOL-DESIGN §3.2, §8.2).
//!
//! [`crate::io::IoManager`] needs one capability from the owning TCP session — issue a
//! Connection-Manager request (ForwardOpen / ForwardClose) over UCMM and hand back the full reply
//! CPF — but the layering forbids `io` from importing `client` (nothing imports upward). The
//! abstraction ([`crate::io::ForwardOpenService`]) therefore lives in `io`; this module supplies the
//! implementation for [`EipClient`], a downward dependency `client → io`. That is the exact
//! dependency inversion that lets `io.forward_open(&client, spec)` type-check without an upward
//! import.

use std::net::IpAddr;

use crate::cip::message::MessageRequest;
use crate::cpf::{Cpf, CpfItem};
use crate::encap::Command;
use crate::error::{EnipError, Result};
use crate::io::ForwardOpenService;
use crate::wire::WireReader;

use super::{encap_data_with_cpf, EipClient};

impl ForwardOpenService for EipClient {
    /// Issue `request` to the Connection Manager over a direct UCMM `SendRRData` transaction and
    /// return the reply's CPF item list — both the Message Router reply and any Sockaddr Info items
    /// the target attaches (§8.2). Routing for an I/O connection lives in the connection path, so the
    /// ForwardOpen itself is sent unwrapped (null address), never inside Unconnected_Send.
    async fn cm_ucmm(&self, request: MessageRequest, extra_items: Vec<CpfItem>) -> Result<Cpf> {
        let mr_bytes = request.encode()?;
        let mut items = vec![CpfItem::null_address(), CpfItem::unconnected_data(mr_bytes)];
        items.extend(extra_items);
        let cpf = Cpf::from_items(items);
        let data = encap_data_with_cpf(&cpf)?;
        let frame = self.transaction(Command::SendRRData, data, "forward_open").await?;
        if !frame.header.status.is_ok() {
            return Err(EnipError::Encap(frame.header.status));
        }
        let mut r = WireReader::with_context(&frame.data, "sendrrdata reply");
        let _interface_handle = r.u32().map_err(EnipError::Malformed)?;
        let _timeout = r.u16().map_err(EnipError::Malformed)?;
        // Decode by the CPF item count WITHOUT asserting end-of-buffer: a real target (OpENer) may
        // append the echoed O→T/T→O Sockaddr Info items to a ForwardOpen *reply* beyond the declared
        // item count on some paths. Honor the count and ignore any trailing bytes rather than failing
        // the whole reply (the counted items — the FO reply + any properly-counted sockaddr items —
        // are all we consume). D-ENIP interop hardening (OpENer live).
        Cpf::decode_from(&mut r).map_err(EnipError::Malformed)
    }

    /// The TCP peer's IP — the default O→T transmit target when the reply carries no O→T sockaddr
    /// redirect. `None` for a byte-stream fixture session.
    fn target_ip(&self) -> Option<IpAddr> {
        self.peer_addr.map(|addr| addr.ip())
    }
}
