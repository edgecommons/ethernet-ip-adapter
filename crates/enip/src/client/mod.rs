//! The explicit-messaging client (PROTOCOL-DESIGN §11).
//!
//! `EipClient` (the caller-facing handle: connect, read/write tag, list tags, get/set attribute,
//! identity, close) and `ClientOptions`. The session actor and connected class-3 path are the
//! submodules below; `client` is the only module besides [`crate::io`] that owns a socket.
//!
//! P1 fills these modules.

pub mod session;
pub mod connected;
