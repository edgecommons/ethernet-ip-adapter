//! CIP Message Router request/reply (PROTOCOL-DESIGN §6.1).
//!
//! `MessageRequest` encode and `MessageReply` decode: service code, request-path words, and the
//! reply's reserved/status/extended-status prefix ahead of the service data.
//!
//! P1 fills this module.
