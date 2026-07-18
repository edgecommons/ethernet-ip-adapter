//! Assembly layout mapping (PROTOCOL-DESIGN §9, D-ENIP-11).
//!
//! `AssemblyLayout`: bounds-checked extraction/insertion of typed fields (offset/type/bit) from raw
//! assembly bytes. Field *naming and configuration* stays in the adapter; only the byte math lives
//! here, inside the fuzz boundary.
//!
//! P1 fills this module.
