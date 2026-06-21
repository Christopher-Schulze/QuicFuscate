# TODO-171: Deployment Guide

## Status
**COMPLETED** - Created `docs/deployment.md` covering prerequisites, building, Linux server setup, systemd, TLS certificates, firewall (iptables/nftables/ufw), QKey management, monitoring/logging, and common operational tasks.

## Severity
**MEDIUM**

## Context
No deployment documentation exists. Users who want to deploy the QuicFuscate server on Linux have no guidance on system requirements, configuration, service management, or security hardening.

- No `docs/deployment.md` or equivalent exists
- `config/server-linux.default.toml` is minimal (only 3 lines)
- Systemd integration exists in code (`src/implementations/server/systemd.rs`) but is undocumented

## Root Cause
Development focus was on implementation rather than operational documentation. The project has outgrown the point where deployment knowledge can remain tribal.

## Fix Plan
1. Create `docs/deployment.md` covering:
   - System requirements (OS versions, dependencies, minimum hardware)
   - Binary installation / building from source
   - Linux server setup (user, permissions, directories)
   - Systemd service configuration (unit file, socket activation)
   - TLS certificate setup (generation, paths, renewal)
   - Firewall rules (required ports, iptables/nftables examples)
   - Configuration reference (all TOML sections with defaults)
   - Monitoring and health checks (admin interface, metrics)
   - Log management (levels, rotation, integration with journald)
   - Security hardening checklist
2. Test deployment guide on a clean Linux system
3. Link from README.md

## Acceptance Criteria
- A new user can deploy the server on Linux by following the guide alone
- All configuration options documented with defaults
- Systemd unit file provided and explained
- TLS setup documented end-to-end
- Firewall rules specified for all required ports

## Dependencies
- TODO-173 (server config template) - expanded config helps deployment docs

## Affected Files
- `docs/deployment.md` (new)
- `README.md` (add link)
