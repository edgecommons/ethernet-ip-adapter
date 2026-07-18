//! Class-1 implicit I/O runtime (PROTOCOL-DESIGN §8.5–§8.7).
//!
//! `IoManager` (UDP socket task), `IoConnection` state, the class-1 frame codec, 16-bit sequence
//! windows, the produce scheduler, and the originator-side inactivity watchdog — every receive
//! check counted, never silent (D-ENIP-7/8/9).
//!
//! P3: class-1 implicit I/O is a later slice; this module is an intentional stub. The Connection
//! Manager codecs it needs ([`crate::cm`]) already exist and were structured so P3 extends them.
