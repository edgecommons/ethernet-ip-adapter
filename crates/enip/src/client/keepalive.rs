//! Class-3 inactivity keepalive (PROTOCOL-DESIGN §7.6, D-ENIP-18).
//!
//! A class-3 ForwardOpen arms an **inactivity watchdog on the target**: `multiplier × O→T API`. If
//! no O→T traffic arrives inside that window the target tears the connection down, and every
//! subsequent request on it fails until the client reconnects. A paused instance — or any poll group
//! whose gap exceeds the window — would silently lose its connection, so the connection's owner (this
//! crate, never the adapter) keeps it alive: when no request has flowed for **¾ of the window**, the
//! session sends a NOP-level read — `Get_Attribute_Single` of the Identity object's Revision
//! attribute, the cheapest mandatory attribute every CIP device serves.
//!
//! The probe rides the ordinary request path ([`crate::client::EipClient::get_attribute_single`] →
//! `send_cip` → `send_connected`), so it is correlated, deadline-bounded, sequence-checked, and
//! refreshes the activity clock exactly like any other request — the keepalive is not a side channel.
//!
//! **Lifecycle.** The task holds a [`Weak`] to the client's inner state and a
//! [`tokio::sync::mpsc::WeakSender`] for the session actor's command channel — never a strong
//! reference to either. It therefore keeps neither the client nor the session actor alive: the
//! instant the caller drops its last [`crate::client::EipClient`], the actor's last strong sender
//! goes with it, the actor exits, and this task returns at its next wake (bounded by
//! [`KEEPALIVE_MAX_SLEEP`]) when the upgrade fails. It also returns as soon as a probe reports the
//! session closed or lost.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::error::EnipError;

use super::session::SessionCommand;
use super::{EipClient, Inner};

/// Identity object class (`0x01`) — the §7.6 keepalive target.
pub(crate) const IDENTITY_CLASS: u16 = 0x01;
/// Identity object instance 1 (every CIP device has exactly one).
pub(crate) const IDENTITY_INSTANCE: u16 = 0x01;
/// Identity attribute 4 (Revision) — a 2-byte mandatory attribute; the cheapest legal read.
pub(crate) const IDENTITY_ATTR_REVISION: u16 = 0x04;

/// The keepalive fires when idle time reaches ¾ of the inactivity window (§7.6): late enough that an
/// ordinarily-polled connection never pays for it, early enough that one lost probe still leaves a
/// quarter-window of margin before the target gives up.
pub(crate) const KEEPALIVE_NUM: u32 = 3;
/// Denominator of the ¾ rule.
pub(crate) const KEEPALIVE_DEN: u32 = 4;

/// Upper bound on any single keepalive sleep, so the task re-checks client liveness (the [`Weak`]
/// upgrade) at least this often even under an enormous window — otherwise a dropped client whose
/// window rounded to "forever" would leave the task parked indefinitely.
pub(crate) const KEEPALIVE_MAX_SLEEP: Duration = Duration::from_secs(60);

/// The far-future fallback for an unrepresentable due-time — mirrors
/// [`crate::client::session::deadline_from`]. "Never due" is the correct reading of a window so large
/// its ¾ point cannot be represented; "due now" (a saturating fallback) would invert it into a probe
/// storm.
const FAR_FUTURE: Duration = Duration::from_secs(31_536_000);

/// Monotonic last-activity tracker: nanoseconds since `base`, stored in an atomic so the client
/// (writer, on every completed class-3 exchange) and the keepalive task (reader) share it without a
/// lock.
pub(crate) struct ActivityTracker {
    /// The instant the connection opened; all stored offsets are relative to it.
    base: Instant,
    /// Nanoseconds since `base` at the last completed exchange.
    last_nanos: AtomicU64,
}

impl ActivityTracker {
    /// A tracker whose activity starts at `now` (the moment the connection opened).
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            base: now,
            last_nanos: AtomicU64::new(0),
        }
    }

    /// Record a completed class-3 exchange at `now`.
    ///
    /// `fetch_max` rather than `store`: two exchanges may complete concurrently, and a marginally
    /// older one must never drag the deadline backwards. A `now` before `base`, or an offset beyond
    /// `u64::MAX` nanoseconds (584 years), saturates rather than wrapping.
    pub(crate) fn touch(&self, now: Instant) {
        let nanos =
            u64::try_from(now.saturating_duration_since(self.base).as_nanos()).unwrap_or(u64::MAX);
        self.last_nanos.fetch_max(nanos, Ordering::Relaxed);
    }

    /// The instant of the last completed exchange.
    pub(crate) fn last(&self) -> Instant {
        let nanos = self.last_nanos.load(Ordering::Relaxed);
        self.base
            .checked_add(Duration::from_nanos(nanos))
            .unwrap_or(self.base)
    }
}

/// The O→T interval a class-3 window is derived from (§7.6).
///
/// The reply's **actual** O→T packet interval is used when it lies within
/// `[MIN_REPLY_API, MAX_REPLY_API]` — that is what the target actually armed its watchdog with.
/// Anything outside that range is not a timer input: it falls back to the (already-clamped)
/// requested RPI. This is the deliberate asymmetry with class-1's
/// [`crate::io::validate_reply_apis`], where an implausible API is a hard `ProtocolViolation`: there
/// the API drives the produce scheduler and the connection watchdog, so a hostile value poisons the
/// connection; here the only timer it feeds is our own keepalive, and explicit messaging has always
/// worked against targets that answer with a wonky API. A bad API forfeits the refinement, never the
/// open.
pub(crate) fn class3_negotiated_interval(
    requested_rpi: Duration,
    success: &crate::cm::ForwardOpenSuccess,
) -> Duration {
    let api = Duration::from_micros(u64::from(success.o_t_api));
    if api >= crate::io::MIN_REPLY_API && api <= crate::io::MAX_REPLY_API {
        api
    } else {
        requested_rpi
    }
}

/// The target-side inactivity window for a class-3 open (§7.6): `multiplier × O→T API`, the API
/// chosen by [`class3_negotiated_interval`].
///
/// The product saturates to [`Duration::MAX`] — an effectively-infinite window, i.e. a target that
/// has opted out of enforcing one, so no keepalive is ever due.
pub(crate) fn class3_inactivity_window(
    requested_rpi: Duration,
    multiplier: crate::cm::TimeoutMultiplier,
    success: &crate::cm::ForwardOpenSuccess,
) -> Duration {
    class3_negotiated_interval(requested_rpi, success)
        .checked_mul(multiplier.multiplier())
        .unwrap_or(Duration::MAX)
}

/// A derived inactivity window below this is implausible for explicit messaging (§7.6): it claims the
/// target tears the connection down after less than a second of quiet, which on an idle session means
/// a probe roughly every ¾ s forever, and leaves a keepalive margin (a quarter of the window, see
/// [`crate::ClientOptions::class3_rpi`]) far under any realistic request round trip.
///
/// One second is a deliberate order-of-magnitude line, not a limit: a plausible explicit-messaging
/// watchdog is measured in seconds to tens of seconds (the default is 32 s), and the smallest value a
/// real target has any reason to arm is still comfortably above this.
pub(crate) const IMPLAUSIBLY_SHORT_WINDOW: Duration = Duration::from_secs(1);

/// PURE: whether a negotiated window is implausibly short — worth one warning, never a refusal.
///
/// The window is **not** clamped or rejected. `[MIN_REPLY_API, MAX_REPLY_API]` is the accepted
/// plausibility band (§8.2), and a value inside it is by contract the watchdog the target says it
/// armed: probing on that cadence is correct behaviour, not a fault, and refusing it would break a
/// connection the target considers healthy. The warning exists because such a window is far more
/// likely to be a misconfigured or buggy peer than an intent, and a silent forever-probe is the kind
/// of thing an operator should be told about once.
pub(crate) fn window_is_implausibly_short(window: Duration) -> bool {
    window < IMPLAUSIBLY_SHORT_WINDOW
}

/// The instant the next keepalive is due: `last_activity + window × ¾`, far-future on overflow.
pub(crate) fn next_keepalive_at(last_activity: Instant, window: Duration) -> Instant {
    let idle = window
        .checked_mul(KEEPALIVE_NUM)
        .and_then(|w| w.checked_div(KEEPALIVE_DEN));
    match idle.and_then(|d| last_activity.checked_add(d)) {
        Some(at) => at,
        None => last_activity
            .checked_add(FAR_FUTURE)
            .unwrap_or(last_activity),
    }
}

/// Whether a keepalive is due at `now` — true exactly **at** the ¾ point, not before.
pub(crate) fn keepalive_due(now: Instant, last_activity: Instant, window: Duration) -> bool {
    now >= next_keepalive_at(last_activity, window)
}

/// Spawn the keepalive task for a connected-messaging client (§7.6).
///
/// Takes a strong [`mpsc::Sender`] purely for convenience at the call site and immediately downgrades
/// it: holding it strong would keep the session actor alive for up to [`KEEPALIVE_MAX_SLEEP`] after
/// the caller dropped its last client handle, delaying the socket's close. The task upgrades it only
/// for the duration of a probe, at which point the caller's own client — proven alive by the
/// [`Weak<Inner>`] upgrade that precedes it — is holding the channel open anyway.
// `pub(super)`, not `pub(crate)`: `Inner` is private to the `client` module, and a `pub(crate)`
// signature naming it would be a private-interface leak.
pub(super) fn spawn(
    tx: mpsc::Sender<SessionCommand>,
    inner: Weak<Inner>,
) -> tokio::task::JoinHandle<()> {
    let weak_tx = tx.downgrade();
    drop(tx);
    tokio::spawn(run(weak_tx, inner))
}

/// The keepalive loop. Every iteration re-reads the shared activity clock, so ordinary request
/// traffic pushes the probe out without the task ever being signalled.
///
/// A failed probe cannot spin the loop: any probe that reached a reply — including a CIP error, a
/// sequence mismatch, or a malformed body — has already touched the activity clock inside
/// `send_connected`, which moves the next due time a whole ¾-window out. The only failures that
/// leave the clock untouched are a timeout or a broken transport, and those are bounded by the
/// session actor's consecutive-timeout ladder, which severs the session (and so ends this task)
/// after `max_consecutive_timeouts` strikes.
async fn run(weak_tx: mpsc::WeakSender<SessionCommand>, inner: Weak<Inner>) {
    // Once, at task start: tell the operator if the negotiated window is implausibly tight. The
    // cadence that follows is correct — it is the watchdog the target claims to have armed, and every
    // iteration awaits a full bounded transaction rather than spinning — but a sub-second explicit
    // messaging watchdog means a probe every ¾ s on an idle session forever, which is worth saying
    // out loud. Warn only: no clamp, no refusal (§8.2's plausibility band is the accepted contract).
    if let Some(strong) = inner.upgrade() {
        if let Some(conn) = strong.connected.as_ref() {
            if window_is_implausibly_short(conn.inactivity_window) {
                let now = Instant::now();
                let probe_interval = next_keepalive_at(now, conn.inactivity_window)
                    .saturating_duration_since(now);
                tracing::warn!(
                    negotiated_o_t_interval_us = conn.negotiated_interval.as_micros(),
                    timeout_multiplier = conn.timeout_multiplier.multiplier(),
                    inactivity_window_ms = conn.inactivity_window.as_millis(),
                    probe_interval_ms = probe_interval.as_millis(),
                    "class-3 inactivity window is implausibly short; the connection will be probed \
                     at three quarters of it for as long as it is idle"
                );
            }
        }
    }
    loop {
        // Compute the wake-up, then release the strong reference: the task must never hold an
        // `Arc<Inner>` across a sleep, or dropping the last client handle would not free the session.
        let (due, window, activity) = {
            let Some(strong) = inner.upgrade() else {
                return;
            };
            let Some(conn) = strong.connected.as_ref() else {
                return;
            };
            let window = conn.inactivity_window;
            let activity = Arc::clone(&conn.activity);
            (next_keepalive_at(activity.last(), window), window, activity)
        };

        // Never sleep past the liveness re-check interval. An unrepresentable cap means "no cap" —
        // never "wake now", which would spin.
        let wake = match Instant::now().checked_add(KEEPALIVE_MAX_SLEEP) {
            Some(cap) => due.min(cap),
            None => due,
        };
        tokio::time::sleep_until(wake).await;

        let Some(strong) = inner.upgrade() else {
            return;
        };
        if !keepalive_due(Instant::now(), activity.last(), window) {
            // Either traffic moved the deadline out, or this was only a MAX_SLEEP liveness re-check.
            continue;
        }
        let Some(tx) = weak_tx.upgrade() else {
            return;
        };

        // A transient client over the same session actor and inner state: the probe therefore rides
        // `send_connected`, feeding the target's watchdog and touching the activity clock like any
        // other request.
        let probe = EipClient {
            tx,
            inner: strong,
            peer_addr: None,
            #[cfg(feature = "tls")]
            tls_info: None,
        };
        let outcome = probe
            .get_attribute_single(IDENTITY_CLASS, IDENTITY_INSTANCE, IDENTITY_ATTR_REVISION)
            .await;
        match outcome {
            // A CIP error reply still proves the exchange flowed both ways — which is the whole
            // point of the probe — and `send_connected` has already touched the activity clock.
            Ok(_) | Err(EnipError::Cip(_)) => {
                probe
                    .inner
                    .stats
                    .keepalives_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(EnipError::Closed | EnipError::ConnectionLost { .. }) => return,
            // Timeout, encapsulation error, malformed reply…: the session actor's own
            // consecutive-timeout ladder is the liveness authority, not this task. Recomputing the
            // due time next iteration is the retry.
            Err(e) => {
                tracing::debug!(error = %e, "class-3 keepalive probe did not complete");
            }
        }
        drop(probe);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::cm::{ForwardOpenSuccess, TimeoutMultiplier};

    fn success_with_o_t_api(o_t_api: u32) -> ForwardOpenSuccess {
        ForwardOpenSuccess {
            o_t_connection_id: 0xAABB_CCDD,
            t_o_connection_id: 0x1122_3344,
            connection_serial: 7,
            vendor_id: 0x1337,
            originator_serial: 0xDEAD_BEEF,
            o_t_api,
            t_o_api: o_t_api,
            app_data: bytes::Bytes::new(),
        }
    }

    /// K4 — the window prefers the reply's actual O→T API, and falls back to the requested RPI for
    /// any value outside the plausible band. A hostile API can never become a timer input, and can
    /// never fail the open.
    #[test]
    fn hostile_reply_api_falls_back_to_requested_rpi() {
        let requested = Duration::from_secs(2);
        // 0 µs — the classic livelock value.
        assert_eq!(
            class3_inactivity_window(requested, TimeoutMultiplier::X16, &success_with_o_t_api(0)),
            Duration::from_secs(32)
        );
        // Below MIN_REPLY_API (100 µs).
        assert_eq!(
            class3_inactivity_window(requested, TimeoutMultiplier::X16, &success_with_o_t_api(99)),
            Duration::from_secs(32)
        );
        // Above MAX_REPLY_API (600 s).
        assert_eq!(
            class3_inactivity_window(
                requested,
                TimeoutMultiplier::X16,
                &success_with_o_t_api(700_000_000)
            ),
            Duration::from_secs(32)
        );
        // A plausible API wins over the requested RPI: 200 ms × 4 = 800 ms.
        assert_eq!(
            class3_inactivity_window(
                requested,
                TimeoutMultiplier::X4,
                &success_with_o_t_api(200_000)
            ),
            Duration::from_millis(800)
        );
        // Exactly on the boundaries — both are accepted (the band is inclusive).
        assert_eq!(
            class3_inactivity_window(requested, TimeoutMultiplier::X4, &success_with_o_t_api(100)),
            Duration::from_micros(400)
        );
        assert_eq!(
            class3_inactivity_window(
                requested,
                TimeoutMultiplier::X4,
                &success_with_o_t_api(600_000_000)
            ),
            Duration::from_secs(2400)
        );
        // Saturation: an unrepresentable product becomes an effectively-infinite window.
        assert_eq!(
            class3_inactivity_window(
                Duration::MAX,
                TimeoutMultiplier::X512,
                &success_with_o_t_api(0)
            ),
            Duration::MAX
        );
    }

    /// A negotiated window under a second is warned about — once, at task start — and never clamped
    /// or refused: it is by contract the watchdog the target says it armed, and the plausibility band
    /// that governs the API is `[MIN_REPLY_API, MAX_REPLY_API]`, not this line.
    #[test]
    fn an_implausibly_short_window_is_flagged_at_the_one_second_line() {
        assert!(window_is_implausibly_short(Duration::from_millis(60)));
        assert!(window_is_implausibly_short(Duration::from_millis(999)));
        assert!(!window_is_implausibly_short(IMPLAUSIBLY_SHORT_WINDOW));
        assert!(!window_is_implausibly_short(Duration::from_secs(32)));
        assert!(!window_is_implausibly_short(Duration::MAX));

        // The shape that reaches it in practice: an in-band but tiny echoed API (5 ms × ×16 = 80 ms).
        let window = class3_inactivity_window(
            Duration::from_secs(2),
            TimeoutMultiplier::X16,
            &success_with_o_t_api(5_000),
        );
        assert_eq!(window, Duration::from_millis(80));
        assert!(window_is_implausibly_short(window));
        // …and the interval the warning names is the echoed one, not what was requested.
        assert_eq!(
            class3_negotiated_interval(Duration::from_secs(2), &success_with_o_t_api(5_000)),
            Duration::from_millis(5)
        );
        // An out-of-band API falls back, and the fallback is what gets named.
        assert_eq!(
            class3_negotiated_interval(Duration::from_secs(2), &success_with_o_t_api(0)),
            Duration::from_secs(2)
        );
    }

    /// K8 — the ¾ boundary matrix: due exactly at the ¾ point, not one tick before; an
    /// effectively-infinite window is never due.
    #[tokio::test(start_paused = true)]
    async fn next_keepalive_at_and_due_boundaries() {
        let base = Instant::now();
        let window = Duration::from_secs(32);
        let due = next_keepalive_at(base, window);
        assert_eq!(due, base + Duration::from_secs(24));

        assert!(!keepalive_due(base, base, window));
        assert!(!keepalive_due(
            base + Duration::from_secs(24) - Duration::from_nanos(1),
            base,
            window
        ));
        assert!(keepalive_due(base + Duration::from_secs(24), base, window));
        assert!(keepalive_due(base + Duration::from_secs(25), base, window));

        // A window whose ¾ point is unrepresentable lands far in the future, never "now".
        let far = next_keepalive_at(base, Duration::MAX);
        assert!(far > base + Duration::from_secs(86_400));
        assert!(!keepalive_due(
            base + Duration::from_secs(86_400),
            base,
            Duration::MAX
        ));

        // A sub-millisecond window still divides exactly.
        assert_eq!(
            next_keepalive_at(base, Duration::from_micros(400)),
            base + Duration::from_micros(300)
        );
    }

    /// The activity clock is monotonic: a later touch moves it forward, an out-of-order older touch
    /// does not move it back, and the initial value is the open instant.
    #[tokio::test(start_paused = true)]
    async fn activity_tracker_is_monotonic() {
        let base = Instant::now();
        let tracker = ActivityTracker::new(base);
        assert_eq!(tracker.last(), base);

        tracker.touch(base + Duration::from_secs(5));
        assert_eq!(tracker.last(), base + Duration::from_secs(5));

        // An older completion must not drag the deadline backwards.
        tracker.touch(base + Duration::from_secs(1));
        assert_eq!(tracker.last(), base + Duration::from_secs(5));

        // A `now` before the base saturates to the base rather than wrapping.
        let later = ActivityTracker::new(base + Duration::from_secs(10));
        later.touch(base);
        assert_eq!(later.last(), base + Duration::from_secs(10));

        tracker.touch(base + Duration::from_secs(11));
        assert_eq!(tracker.last(), base + Duration::from_secs(11));
    }
}
