//! Encapsulation layer (PROTOCOL-DESIGN §5).
//!
//! The 24-byte encapsulation header, the command set, the session lifecycle, and the typed
//! `EncapStatus` codes. Multi-byte fields are little-endian (the sockaddr-info big-endian exception
//! lives in [`crate::cpf`]).
//!
//! P1 fills this module.

pub mod codec;
