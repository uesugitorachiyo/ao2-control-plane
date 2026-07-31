# AO2 Control Plane Deployment Instructions

## Scope

This directory contains operator-reviewed service templates and reverse-proxy examples. It does not confer authority to install, start, expose, or change a live service.

## Rules

- Keep examples portable, least-privileged, loopback/private by default, and explicit about native-TLS absence and trusted proxy requirements.
- Never embed real bearer tokens, signing keys, credentials, account identifiers, hostnames, or user-specific paths. Preserve placeholder-only environment files.
- Installation, service-manager changes, firewall or proxy changes, public exposure, credential rotation, and live deployment require separate operator authority and rollback planning.
- Validate platform syntax and documentation for the files changed. Do not run install, enable, start, restart, or remote commands during an instruction-only change.
- Any deployment change must preserve authenticated APIs, protected data paths, file permissions, logs, health checks, and an explicit reversal path.
