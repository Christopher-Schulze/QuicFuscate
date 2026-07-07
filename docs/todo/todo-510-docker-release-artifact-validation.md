---
id: TODO-510
title: Docker release artifact validation without local Docker dependency
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-07-02
depends_on: [TODO-447, TODO-509]
---

# TODO-510: Docker Release Artifact Validation Without Local Docker Dependency

## Context

Docker artifacts remain in the repository for GitHub/CI image work and explicit
operator use. Local Docker is not required on the development Mac. The retained
artifact surface still needs real validation before Docker can count as a
production-ready deployment path.

## Desired Outcome

- Docker image build and basic runtime behavior are validated in GitHub Actions
  or an explicit remote Linux environment.
- The validation proves the binary starts, config mounts work, required runtime
  tools exist, TUN prerequisites are clearly checked, and secrets are not baked
  into the image.
- Docker remains the only retained container artifact surface.

## Implementation Plan

1. Inspect current `Dockerfile`, `.dockerignore`, and `docker-compose.yml`.
2. Decide the validation environment:
   - Preferred: GitHub Actions job using hosted Linux runner where Docker is
     available.
   - Alternative: Broderick or another explicit remote Linux host if Docker is
     installed there by user approval.
3. Add or harden a CI job that:
   - builds the image,
   - prints image size,
   - verifies `/usr/local/bin/quicfuscate --help`,
   - verifies `iptables`, `nft`, and `ip` availability,
   - runs the server command in dry/startup mode where possible without
     requiring privileged local Mac setup,
   - verifies no obvious secrets are copied into layers from config examples.
4. If a privileged TUN test is impossible in CI, mark that gap explicitly and
   add a remote-only follow-up command rather than pretending it passed.
5. Update `docs/DOCUMENTATION.md`, `docs/todo.md`, and TODO-447 with the real
   Docker validation level.

## Acceptance Criteria

- Docker image build succeeds in the selected non-local validation environment.
- Image size is recorded.
- Runtime binary starts and reports version/help.
- Required networking tools are present in the image.
- Secrets are not present in the image layers by static scan.
- Any TUN/capability limitation is documented as a real limitation, not hidden.
- No local Docker installation or local Docker run is required.

## Verification Commands

| Command | Expected Result |
|---------|-----------------|
| `docker build -t quicfuscate/server:ci .` | PASS in CI or approved remote environment |
| `docker image inspect quicfuscate/server:ci` | image size recorded |
| `docker run --rm quicfuscate/server:ci sh -lc 'quicfuscate --help'` | PASS (binary reports Usage) |
| `docker run --rm quicfuscate/server:ci sh -lc 'command -v iptables && command -v nft && command -v ip'` | PASS |
| static secret scan over image/exported layers | no committed secrets |

## Non-Goals

- Do not install Docker locally on the development Mac.
- Do not reintroduce removed stale deployment-manifest directories.
- Do not claim privileged TUN validation unless it actually ran.

## Preparation Evidence (2026-07-03)

**Status: OPEN (prepared) — CI job created, awaiting first GitHub Actions run.**

- `.github/workflows/docker-validation.yml` created with 6 validation steps:
  1. `docker build -t quicfuscate/server:ci .` — image build
  2. `docker image inspect` — image size recorded to GITHUB_STEP_SUMMARY
  3. `docker run --rm quicfuscate/server:ci sh -lc 'quicfuscate --help'` — binary starts, reports Usage (must use `sh -lc` because the Dockerfile ENTRYPOINT is `tini --`, so `--help` as a direct arg would replace CMD and produce `tini -- --help` which fails)
  4. `docker run --rm ... command -v iptables && command -v nft && command -v ip` — networking tools present
  5. Static secret scan — checks for .pem/.key/.env files in image layers
  6. Default config template verification — confirms `/etc/quicfuscate/quicfuscate.toml.default` exists
- Triggers: PRs touching Dockerfile/.dockerignore/docker-compose.yml, and `workflow_dispatch`.
- Does NOT validate privileged TUN/UDP bind (requires `--device /dev/net/tun` + `--cap-add NET_ADMIN`); this is documented as a real limitation in the workflow comments.
- Dockerfile inspected: multi-stage build (rust:bookworm builder → debian:bookworm-slim runtime), runs as unprivileged `quicfuscate` user, tini entrypoint, healthcheck on admin HTTP.

**Remaining for DONE:** First successful GitHub Actions run of `docker-validation.yml`. This requires a push/PR that touches the Docker paths, or a manual `workflow_dispatch` trigger.

