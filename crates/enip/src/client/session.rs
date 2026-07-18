//! The session actor (PROTOCOL-DESIGN §11.1, §10.3–§10.4).
//!
//! Owns the TCP writer + reader, `sender_context` correlation with one in-flight request, the
//! `Connecting -> Registered -> Closing -> Closed` state machine, per-request deadlines, and
//! stale-reply quarantine (D-ENIP-5/6) — a late reply is never delivered as another request's
//! answer.
//!
//! P1 fills this module.
