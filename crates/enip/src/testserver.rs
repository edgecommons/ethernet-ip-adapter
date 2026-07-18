//! In-crate mock target — `testserver` feature (PROTOCOL-DESIGN §12.5, D-ENIP-14).
//!
//! A minimal explicit-messaging responder + class-1 producer/consumer used by the state-machine
//! tests and as the adapter's push-validation fallback. It is a test double, not a product, so it
//! is behind a feature and never linked into the release binary. `testserver` may reach any module
//! (it is a peer for the whole stack).
//!
//! P1 adds the module body.
