//! CIP General Status (PROTOCOL-DESIGN §6.4).
//!
//! A TYPED `GeneralStatus` enum plus extended-status words — a status is data the caller inspects,
//! not a stringified message. `0x06` (partial transfer) drives fragmented reads (D-ENIP-12).
//!
//! P1 fills this module.
