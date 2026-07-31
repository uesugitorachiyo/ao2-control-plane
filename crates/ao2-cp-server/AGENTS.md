# AO2 Control Plane Server Instructions

## Scope

This crate owns authenticated ingestion, validation, read APIs, dashboards, audit surfaces, and process configuration. It is an observer service, not an AO2 control API.

## Rules

- Authenticate every `/api/v1/*` route and keep tokens out of URLs, logs, errors, metrics, dashboards, fixtures, and responses.
- Validate body limits, content type, schema, signature, digest, provenance, and authority flags before storage. Reject the request on ambiguity or drift.
- Never add an endpoint that approves, closes, retries, schedules, executes, or mutates an AO2 run. Derived readiness and release views remain explicitly non-authorizing.
- Preserve deterministic response contracts, redaction, audit events, cache safety, and shutdown behavior. Do not leak raw uploads or private paths in diagnostics.
- Server tests: `cargo test -p ao2-cp-server`. Run the repository-wide format, workspace-test, and Clippy gates before completion.
