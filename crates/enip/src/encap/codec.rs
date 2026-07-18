//! TCP framing codec for the encapsulation layer (PROTOCOL-DESIGN §5.1).
//!
//! A `tokio_util` `Encoder`/`Decoder`: read 24 bytes, cap `length <= 65511` *before* buffering (a
//! hostile length cannot over-allocate), skip `NOP` frames, and treat a truncated header as a lost
//! connection.
//!
//! P1 fills this module.
