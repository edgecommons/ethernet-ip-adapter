//! EPATH encoding (PROTOCOL-DESIGN §6.2).
//!
//! Segment enum + `EPath` builder + the padded encoder CIP messaging uses, plus the symbolic
//! Logix tag-path parser. v1 restricts routing to port numbers <= 14 (D-ENIP-13).
//!
//! P1 fills this module.
