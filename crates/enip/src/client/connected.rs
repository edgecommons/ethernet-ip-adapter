//! Connected class-3 explicit messaging (PROTOCOL-DESIGN §7.6).
//!
//! A ForwardOpen'd (transport class 3, application-triggered) explicit path carried over
//! `SendUnitData`. Each request stamps the 16-bit connected-data sequence count (skipping 0); the
//! reply's sequence **and** connection id are matched with a hard `Err`-on-mismatch check — never a
//! `debug_assert!` (D-ENIP-5). A mismatch is discarded, counted (`connected_seq_mismatches`), and
//! surfaced as [`EnipError::ProtocolViolation`], never delivered as the answer.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::cip::message::{MessageReply, MessageRequest};
use crate::cm::{ForwardCloseRequest, ForwardOpenRequest, ForwardOpenSuccess, ForwardRequestFail};
use crate::cpf::{Cpf, CpfItem, ItemType};
use crate::encap::{Command, EncapFrame};
use crate::error::{EnipError, Result};
use crate::wire::{WireReader, WireWriter};

use super::keepalive::{class3_inactivity_window, class3_negotiated_interval, ActivityTracker};
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
    /// The target-side inactivity window: `multiplier × O→T API` (the reply's actual API when
    /// plausible, else the requested RPI). Drives the ¾-window keepalive (§7.6).
    pub(super) inactivity_window: Duration,
    /// The O→T interval the window was derived from — the reply's **actual** packet interval when it
    /// was plausible, else the requested RPI. Retained so the keepalive task can name the negotiated
    /// values when it warns about an implausibly tight window.
    pub(super) negotiated_interval: Duration,
    /// The timeout-multiplier code the ForwardOpen carried, the other factor of the window. Retained
    /// for the same warning.
    pub(super) timeout_multiplier: crate::cm::TimeoutMultiplier,
    /// Elapsed-time tracker of the last completed class-3 exchange, shared with the keepalive task.
    pub(super) activity: Arc<ActivityTracker>,
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
    ///
    /// The requested packet interval and timeout-multiplier code come from [`ClientOptions`]; the
    /// pair fixes the target's inactivity watchdog, and therefore the cadence of the keepalive that
    /// keeps the connection off it.
    pub(super) async fn open_class3(&self, opts: &ClientOptions) -> Result<ConnectedState> {
        let t_o_connection_id = rand::random::<u32>() | 1;
        let connection_serial = rand::random::<u16>() | 1;
        let originator_serial = rand::random::<u32>();
        let base = crate::cm::message_router_path();
        let path = match &opts.route {
            Some(route) => route.prefixed(base),
            None => base,
        };
        // One clamp, up front: the requested RPI is bounded by the same plausible band a reply API
        // must fall in (§8.2), so neither the wire value nor the derived window can be pathological.
        let rpi = opts
            .class3_rpi
            .clamp(crate::io::MIN_REPLY_API, crate::io::MAX_REPLY_API);
        // Infallible after the clamp (600 s = 6e8 µs, well inside u32); the fallback exists only to
        // express that without `expect`.
        let rpi_micros = u32::try_from(rpi.as_micros()).unwrap_or(600_000_000);
        let open = ForwardOpenRequest::class3(
            0,
            t_o_connection_id,
            connection_serial,
            opts.vendor_id,
            originator_serial,
            path,
            rpi_micros,
            opts.class3_timeout_multiplier,
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
        // Verify the originator echo quad before adopting the target-assigned O→T id (§8.2,
        // D-ENIP-16): a reply that does not echo our identity belongs to some other connection and
        // must never bind this one. Class-3 checks only the echo — the reply's actual packet
        // intervals are consulted afterwards for the keepalive window alone (§7.6), and an
        // implausible one falls back rather than failing the open. On a mismatch the target still
        // believes a connection is open, so a best-effort ForwardClose goes out first.
        if let Err(e) = crate::cm::verify_forward_open_echo(&open, &success) {
            let close = ForwardCloseRequest::for_open(&open);
            if let Ok(data) = close.encode() {
                let mr = MessageRequest::new(
                    crate::cm::service::FORWARD_CLOSE,
                    super::connection_manager_path(),
                    data,
                );
                let _ = self.send_unconnected(mr, "forward_close").await;
            }
            return Err(e);
        }
        let inactivity_window =
            class3_inactivity_window(rpi, opts.class3_timeout_multiplier, &success);
        Ok(ConnectedState {
            o_t_connection_id: success.o_t_connection_id,
            t_o_connection_id,
            sequence: AtomicU16::new(0),
            open_request: open,
            inactivity_window,
            negotiated_interval: class3_negotiated_interval(rpi, &success),
            timeout_multiplier: opts.class3_timeout_multiplier,
            activity: Arc::new(ActivityTracker::new(tokio::time::Instant::now())),
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
        // Activity = any *completed* class-3 transaction, including one whose MessageReply carries a
        // non-OK CIP status: the reply proves traffic flowed both ways, which is exactly what the
        // target's inactivity watchdog measures. A request that timed out or broke the transport
        // deliberately does not touch — the keepalive may then fire though bytes did flow, which
        // costs one tiny read (§7.6).
        conn.activity.touch(tokio::time::Instant::now());
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
