//! Connected class-3 explicit messaging (PROTOCOL-DESIGN §7.6).
//!
//! A ForwardOpen'd (transport class 3, application-triggered) explicit path carried over
//! `SendUnitData`. Each request stamps the 16-bit connected-data sequence count (skipping 0); the
//! reply's sequence **and** connection id are matched with a hard `Err`-on-mismatch check — never a
//! `debug_assert!` (D-ENIP-5). A mismatch is discarded, counted (`connected_seq_mismatches`), and
//! surfaced as [`EnipError::ProtocolViolation`], never delivered as the answer.

use std::sync::atomic::{AtomicU16, Ordering};

use crate::cip::message::{MessageReply, MessageRequest};
use crate::cm::{ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess, ForwardRequestFail};
use crate::cpf::{Cpf, CpfItem, ItemType};
use crate::encap::{Command, EncapFrame};
use crate::error::{EnipError, Result};
use crate::wire::{WireReader, WireWriter};

use super::session::SessionStats;
use super::{ClientOptions, EipClient};

/// Live class-3 connection state (§7.6).
pub(crate) struct ConnectedState {
    /// O→T connection id (target-assigned) — the address we send to.
    o_t_connection_id: u32,
    /// T→O connection id (ours) — the address the reply must carry.
    t_o_connection_id: u32,
    /// The connected-data sequence counter (16-bit, skips 0).
    sequence: AtomicU16,
    /// The ForwardOpen we issued, retained to build the matching ForwardClose.
    open_request: ForwardOpenRequest,
}

impl ConnectedState {
    /// The next connected-data sequence count (never 0, §7.6).
    fn next_sequence(&self) -> u16 {
        let mut v = self.sequence.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if v == 0 {
            v = self.sequence.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        }
        v
    }
}

impl EipClient {
    /// Open a connected class-3 connection to the Message Router (§7.6) via a UCMM ForwardOpen.
    pub(super) async fn open_class3(&self, opts: &ClientOptions) -> Result<ConnectedState> {
        let t_o_connection_id = rand::random::<u32>() | 1;
        let connection_serial = rand::random::<u16>() | 1;
        let originator_serial = rand::random::<u32>();
        let base = crate::cm::message_router_path();
        let path = match &opts.route {
            Some(route) => route.prefixed(base),
            None => base,
        };
        let open = ForwardOpenRequest::class3(
            0,
            t_o_connection_id,
            connection_serial,
            opts.vendor_id,
            originator_serial,
            path,
        );
        let mr = MessageRequest::new(open.service(), super::connection_manager_path(), open.encode()?);
        let reply = self.send_unconnected(mr, "forward_open").await?;
        reply.expect_service(open.service())?;
        if !reply.status.is_ok() {
            let fail = ForwardRequestFail::decode(&reply.data).ok();
            return Err(EnipError::ForwardOpenRejected {
                status: reply.status,
                remaining_path_size: fail.and_then(|f| f.remaining_path_size),
            });
        }
        let success = ForwardOpenSuccess::decode(&reply.data)?;
        Ok(ConnectedState {
            o_t_connection_id: success.o_t_connection_id,
            t_o_connection_id,
            sequence: AtomicU16::new(0),
            open_request: open,
        })
    }

    /// Connected class-3 send (§7.6) — a sequence-counted request over `SendUnitData`.
    pub(super) async fn send_connected(
        &self,
        conn: &ConnectedState,
        mr: MessageRequest,
        op: &'static str,
    ) -> Result<MessageReply> {
        let seq = conn.next_sequence();
        let mr_bytes = mr.encode()?;
        let mut connected_data = WireWriter::with_capacity(mr_bytes.len().saturating_add(2));
        connected_data.u16(seq);
        connected_data.put_slice(&mr_bytes);
        let cpf = Cpf::from_items(vec![
            CpfItem::connected_address(conn.o_t_connection_id),
            CpfItem::connected_data(connected_data.into_bytes()),
        ]);
        let data = super::encap_data_with_cpf(&cpf)?;
        let frame = self.transaction(Command::SendUnitData, data, op).await?;
        parse_connected_reply(&frame, seq, conn.t_o_connection_id, &self.inner.stats)
    }

    /// Best-effort ForwardClose for a connected class-3 path (§8.8).
    pub(super) async fn forward_close(&self, conn: &ConnectedState) -> Result<()> {
        let close = ForwardCloseRequest::for_open(&conn.open_request);
        let mr = MessageRequest::new(
            crate::cm::service::FORWARD_CLOSE,
            super::connection_manager_path(),
            close.encode()?,
        );
        let _ = self.send_unconnected(mr, "forward_close").await?;
        Ok(())
    }
}

/// Decode a connected class-3 reply frame, enforcing the connected-data sequence + connection-id
/// match (D-ENIP-5): a mismatch is discarded and counted, never delivered.
fn parse_connected_reply(
    frame: &EncapFrame,
    expected_seq: u16,
    expected_addr: u32,
    stats: &SessionStats,
) -> Result<MessageReply> {
    if !frame.header.status.is_ok() {
        return Err(EnipError::Encap(frame.header.status));
    }
    let mut r = WireReader::with_context(&frame.data, "sendunitdata reply");
    let _interface_handle = r.u32()?;
    let _timeout = r.u16()?;
    let cpf = Cpf::decode(r.take_rest()).map_err(EnipError::Malformed)?;

    let addr_item = cpf
        .find(ItemType::ConnectedAddress)
        .ok_or(EnipError::ProtocolViolation {
            detail: "connected reply missing connected-address item",
        })?;
    let data_item = cpf
        .find(ItemType::ConnectedData)
        .ok_or(EnipError::ProtocolViolation {
            detail: "connected reply missing connected-data item",
        })?;

    let mut ar = WireReader::with_context(&addr_item.data, "connected address");
    let reply_addr = ar.u32().map_err(EnipError::Malformed)?;

    let mut dr = WireReader::with_context(&data_item.data, "connected data");
    let seq_reply = dr.u16().map_err(EnipError::Malformed)?;
    let mr_bytes = dr.take_rest();

    if seq_reply != expected_seq || reply_addr != expected_addr {
        stats.connected_seq_mismatches.fetch_add(1, Ordering::Relaxed);
        return Err(EnipError::ProtocolViolation {
            detail: "connected-data sequence/connection-id mismatch",
        });
    }
    MessageReply::decode(mr_bytes).map_err(EnipError::Malformed)
}
