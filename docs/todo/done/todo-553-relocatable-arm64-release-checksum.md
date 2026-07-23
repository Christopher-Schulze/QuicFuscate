---
id: TODO-553
title: Make ARM64 release checksum sidecars relocatable
severity: CRITICAL
phase: S
priority: P0
status: DONE
created: 2026-07-23
depends_on: []
---

# TODO-553: Make ARM64 Release Checksum Sidecars Relocatable

## Why

Release Build run `30013569998` produced the native ARM64 bundle successfully, but its downloaded `.sha256` sidecar names `scripts/out/build/<bundle>` instead of the adjacent bundle basename. GitHub extracts both artifact files into one clean directory, so the documented direct `sha256sum -c` verification fails before deployment. This makes the distributed integrity proof location-dependent.

## Acceptance

- Generate the ARM64 sidecar from the bundle directory and store only the adjacent bundle basename.
- Keep the sidecar filename exactly `<bundle>.sha256` and preserve standard `sha256sum -c` compatibility.
- Do not weaken, bypass, or duplicate the release bundle hash; the sidecar must cover the uploaded tarball bytes exactly.
- Prove a fresh GitHub artifact download verifies directly from its extraction directory without recreating CI-internal paths.
- Preserve x86_64 checksums, optional signing, release version validation, required native jobs, and all protected UI files.

## Completion Gates

- Regression gate: shell syntax and workflow review prove the sidecar is generated after entering the bundle directory and contains no slash.
- Artifact gate: a new exact-commit ARM64 Release Build succeeds; the downloaded sidecar and tarball pass `sha256sum -c` in a clean temporary directory.
- Native gate: the same Release Build retains successful required ARM64, x86_64, and Windows release jobs.
- Truth gate: TODO consistency, runtime guardrails, diff integrity, protected UI diff, and owning documentation all pass with exact run, commit, artifact, and SHA-256 evidence.

## Sub-Tasks

- [x] Reproduce the broken downloaded sidecar from Release Build run `30013569998`.
- [x] Generate a basename-only checksum from the bundle directory.
- [x] Run local workflow, shell, TODO, runtime, and protected-UI gates.
- [x] Prove direct verification from a fresh exact-commit GitHub artifact.
- [x] Flush documentation and close only with exact evidence.

## Notes

- Broken artifact: `quicfuscate-server-bundle-linux-arm64-0.4.3-20260723_140023.tar.gz`; the tarball SHA-256 is `9eae0ee5f78957d11c2e6f2bfb6d177ea78204d98ecef360651c826480f86ebb`.
- The workflow now changes into the bundle directory before hashing and writes only `bundle_name` into the adjacent sidecar. A clean local contract simulation passed direct `sha256sum -c`; workflow YAML parsing, TODO consistency, runtime guardrails, diff integrity, and protected UI checks are green.
- Exact implementation checkpoint `f5d1f69` passed CI run `30014194010`, Clippy Matrix run `30014194240`, and Release Build run `30014193928`. Required Linux x86_64, Linux ARM64, and Windows release jobs succeeded.
- Fresh artifact `8566431013` contains `quicfuscate-server-bundle-linux-arm64-0.4.3-20260723_140808.tar.gz`. The bundle SHA-256 is `7e5cfb182ce7da750c02626357da683f225ae852334cdc6ca878f530eaaaa5bf`; the adjacent sidecar SHA-256 is `0cd4e154e8c0fd2ba28e8dce852c4c3cac9e067e6f87834f2b2c9875f53c1fd8`; the packaged binary SHA-256 is `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`. Direct `sha256sum -c` passed from a clean extraction directory with a basename-only target.
- Follow-up artifact `8567521170` from `f7af807` independently passed adjacent local and Omega verification. Its bundle SHA-256 is `3fb06437e4f1420bc2f975164d87d067513fb5b7de5a860037527b27fa596a41`, sidecar SHA-256 is `15fa4748402dff2a48c678bbb5dee8c0bb694bf0be049610b394d040cabf616b`, and packaged binary SHA-256 remains `8b6ff22e0f410ac6cd5c553786bd5c7584d99c6da0f346a46d9e8839a9e1c2b1`.

## Deviations

None.
