//! ao2-cp-schema: wire-format schemas and validation for ao2-control-plane.
//!
//! All schemas are stable, namespaced by their `*.v1` identifier, and
//! serialize via [`canonical`] (`ao2-canonical-v1`) for content addressing.
//! Canonical JSON is the single source of truth for digests — bundle
//! SHA-256s, signature payloads, and offline-verifier byte-identity
//! checks all hash the AO2 canonical JSON v1 form.
//!
//! # Modules
//! - [`acceptance`] — provider-pilot acceptance evidence
//!   (`ao2.cp-acceptance.v1`)
//! - [`canonical`] — AO2 canonical JSON v1 serializer used for
//!   all digests
//! - [`control_plane`] — control-plane bundle envelopes
//! - [`error`] — typed validation errors with stable JSON shape
//! - [`memory`] — AO2 memory exports (`ao2.memory-export.v1`) and
//!   signed wrapper variants
//! - [`responses`] — server response envelopes for ingest +
//!   list endpoints

pub mod acceptance;
pub mod canonical;
pub mod control_plane;
pub mod error;
pub mod memory;
pub mod responses;
