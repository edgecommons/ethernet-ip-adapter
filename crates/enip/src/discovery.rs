//! Device discovery (PROTOCOL-DESIGN §5.3).
//!
//! ListIdentity / ListServices / ListInterfaces parsing into a typed `DeviceIdentity` (vendor and
//! device-type rendered through a small known-values table plus `Unknown(raw)`).
//!
//! P1 fills this module.
