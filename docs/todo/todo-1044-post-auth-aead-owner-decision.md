---
id: TODO-1044
title: Post-auth AEAD owner decision rustls default stays
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1033, TODO-1038, TODO-1040, TODO-1041, TODO-1043]
---

# TODO-1044: Post-auth AEAD owner decision

## Why

After the bakeoff, profile, stealth residue, integration contract, and optional next-gen re-bench, one written owner decision is required. The ship default stays rustls AES-GCM. This task only picks the opt-in post-auth owner, or refuses one.

## Inputs

- TODO-1033 default is already standard rustls AES-GCM
- TODO-1038/1043 P1 1400 B table
- TODO-1040 distinguisher result
- TODO-1041 unique-hook result
- TODO-885 machine already exists and stays inert until this freeze

## Decision rule

Pick exactly one:

1. `none`: no private family. `aead_preference="auto"` stays `None`. TODO-885 stays inert. This is the expected outcome unless a private owner clearly wins.
2. `opt-in S-AEGIS`: standard libaegis/aegis, feature-gated, never default.
3. `opt-in N-AEGIS` or `opt-in N-MORUS`: next-gen first-party, feature-gated, never default.
4. `opt-in C-*`: current first-party, only if N-* was skipped and C-* still beats S-* and rustls on P1.

A private pick also needs:

- >=10 percent P1 1200-1400 B gain over R-RING and R-LC on both ARM hosts, or a documented unique 1041 hook that rustls cannot provide
- no cheap 1040 distinguisher if the operator goal is max stealth (max-stealth deployments stay on rustls even if a private owner exists)
- FEC epoch isolation proven
- TODO-1029 pcap before any production enable

## Acceptance

- [ ] One written pick from the four options
- [ ] Table of rejected options with one-line reasons
- [ ] Config mapping: default remains `packet_protection_mode=standard`
- [ ] If a private pick exists: `advanced-aead` feature, explicit `aead_preference`, `auto` still does not silently upgrade max-stealth defaults
- [ ] TODO-1028 records the same freeze or refuse
- [ ] TODO-885 is not enabled on the shipped default
- [ ] Docs call the private owner a QuicFuscate opt-in, never a QUIC standard

## Sub-Tasks

- [ ] Collect 1038/1040/1041/1043 artifacts
- [ ] Apply the rule without changing it after seeing numbers
- [ ] Update TODO-884, TODO-885, TODO-1028, TODO-1030
- [ ] Do not flip TODO-1033

## Notes

Max stealth and max performance can disagree. If they disagree, ship two configs: default stealth = rustls AES-GCM; explicit performance profile may opt into the private owner. Never merge those into a silent `auto`.
