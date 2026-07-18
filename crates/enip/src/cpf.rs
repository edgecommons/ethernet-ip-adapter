//! Common Packet Format (PROTOCOL-DESIGN §5.4).
//!
//! Generic item-list encode/decode (`u16 item_count`, then typed items) with per-item bounds
//! checks; consumers assert the shape they need. Includes the sockaddr-info big-endian exception.
//!
//! P1 fills this module.
