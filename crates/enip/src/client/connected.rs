//! Connected class-3 explicit messaging (PROTOCOL-DESIGN §7.6).
//!
//! The ForwardOpen'd explicit path: connected-data sequence counting with a hard match check
//! (never a `debug_assert!`), carried over `SendUnitData`.
//!
//! P1 fills this module.
