//! CIP elementary data types (PROTOCOL-DESIGN §6.3).
//!
//! `CipType` codes and `CipValue`, with checked value decode/encode. Decode is by the wire-declared
//! type, not caller expectation (D-ENIP-4); a mismatch becomes data, not a decode error.
//!
//! P1 fills this module.
