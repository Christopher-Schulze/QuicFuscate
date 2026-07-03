# Remote Proof Runbook — TODO-510 / TODO-512 / TODO-513

This runbook contains the exact commands, expected outputs, and close criteria
for the three remaining `OPEN (prepared)` TODOs that require remote
infrastructure. Copy-paste each section onto the target host, capture the
output, and update the corresponding TODO detail file with the evidence.

**Current commit:** `65ccc3d` (or later — check `git log -1` on the target).
**Prerequisite:** All local gates green (`cargo build --lib`, `cargo clippy
--workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets
--features rust-tests`, `audit-todo-consistency.sh`).

---

## TODO-510: Docker Release Artifact Validation

**Target:** GitHub Actions `ubuntu-latest` runner (no local Docker needed).
**Trigger:** PR touching `Dockerfile` / `.dockerignore` / `docker-compose.yml`
/ `.github/workflows/docker-validation.yml`, OR manual `workflow_dispatch`.

### Step 1 — Trigger the workflow

```bash
# Option A: manual dispatch via gh CLI
gh workflow run docker-validation.yml

# Option B: create a throwaway PR touching a Docker path
git checkout -b chore/docker-validation-trigger
touch Dockerfile  # trivial change to trigger the path filter
git add Dockerfile
git commit -m "chore: trigger docker-validation workflow"
git push -u origin chore/docker-validation-trigger
gh pr create --title "chore: trigger docker-validation" --body "TODO-510 proof run"
```

### Step 2 — Monitor the run

```bash
gh run list --workflow=docker-validation.yml --limit 1
gh run watch <run-id>
```

### Step 3 — Verify expected output

| Step | Expected Result |
|------|-----------------|
| `Build Docker image` | PASS, image `quicfuscate/server:ci` built |
| `Record image size` | size printed to `GITHUB_STEP_SUMMARY` |
| `Verify binary starts and reports help` | `--help` output contains `Usage` |
| `Verify required networking tools` | `iptables`, `nft`, `ip` all present |
| `Static secret scan over image layers` | no `.pem`/`.key`/`.env` files found |
| `Verify config is a default template` | `/etc/quicfuscate/quicfuscate.toml.default` exists |

### Step 4 — Close TODO-510

Update `docs/todo/todo-510-*.md`:
- Change `status: OPEN` to `status: DONE` in frontmatter.
- Append a `## Execution Evidence` section with: run URL, commit SHA, all 6 step results, image size.
- Update `docs/todo.md` row for TODO-510 to `**DONE**` with run URL.

### Known limitations (document, do not hide)

- TUN device creation (`--device /dev/net/tun` + `--cap-add NET_ADMIN`) is
  not tested in CI — requires privileged runner. This is a real limitation.
- Full server startup with UDP bind is not tested in CI — requires
  `--network host` or port mapping with real cert/key.

---

## TODO-512: Broderick Production Soak and Chaos Proof

**Target:** Broderick (or equivalent remote Linux host with root, netns, TUN).
**Minimum duration:** ~3 hours (full matrix).
**Prerequisites:** SSH access, root privileges, two available network
namespaces, `tcpdump` installed, ~2GB free disk for pcap/log captures.

### Step 1 — Pull latest code on Broderick

```bash
ssh broderick
cd /path/to/QuicFuscate
git pull origin main
git log -1 --oneline  # record commit SHA for evidence
```

### Step 2 — Build release binary

```bash
cargo build --release
# Verify binary
./target/release/quicfuscate --help | head -5
```

### Step 3 — Dry-run the soak script (structure validation)

```bash
bash scripts/tests/suites/test-runtime-soak-chaos.sh --dry-run --output-dir /tmp/soak-dryrun
# Expected: script prints planned steps and exits 0 without executing
```

### Step 4 — Fast validation (5-10 min, optional pre-flight)

```bash
bash scripts/tests/suites/test-runtime-soak-chaos.sh --fast --output-dir /tmp/soak-fast
# Expected: reduced iterations pass, no errors in output dir
```

### Step 5 — Full soak matrix (~3 hours)

```bash
mkdir -p /tmp/soak-full
bash scripts/tests/suites/test-runtime-soak-chaos.sh \
  --iterations 10 \
  --admin-iterations 5 \
  --output-dir /tmp/soak-full \
  2>&1 | tee /tmp/soak-full/soak-console.log
```

### Step 6 — Verify expected results

| Scenario | Min Duration | Expected Proof |
|----------|-------------|----------------|
| Clean baseline tunnel | 60 min | stable ping/DNS/throughput, no reconnect churn |
| Loss/jitter adversity | 60 min | FEC adapts, tunnel remains usable |
| Reconnect loop | 30 min | sessions clean up, no leaked clients |
| QKey revoke during traffic | 15 min | revoked session closes, new auth rejects |
| Server restart | 15 min | clean shutdown/restart, client reconnects |
| DNS leak assertion | full run | `raw_port_53_packets=0` in tcpdump counter |
| Resource tracking | full run | RSS/FD/tasks bounded or explained |

### Step 7 — Capture resource tracking

```bash
# During the soak, sample RSS/FD/tasks every 60s:
while true; do
  date -Iseconds >> /tmp/soak-full/resource-samples.log
  ps -o rss,vsz,nlwp,fds -p $(pgrep -f quicfuscate) >> /tmp/soak-full/resource-samples.log
  sleep 60
done
# After soak, verify no unbounded growth:
awk 'NR>1{rss=$2} END{print "Final RSS:", rss, "KB"}' /tmp/soak-full/resource-samples.log
```

### Step 8 — DNS leak verification

```bash
# The soak script runs tun-e2e-dns-leak-netns.sh; verify:
grep "raw_port_53_packets" /tmp/soak-full/*.log
# Expected: raw_port_53_packets=0
```

### Step 9 — Close TODO-512

Update `docs/todo/todo-512-*.md`:
- Change `status: OPEN` to `status: DONE` in frontmatter.
- Append `## Execution Evidence` with: host name, commit SHA, start/end timestamps, total duration, per-scenario pass/fail, RSS/FD bounds, DNS leak counter.
- Update `docs/todo.md` row for TODO-512 to `**DONE**`.

### Failure handling

If any scenario fails:
1. Capture full logs from `/tmp/soak-full/`.
2. Create a new TODO with the failure summary and minimized repro.
3. Do NOT mark TODO-512 as DONE — leave it OPEN with the failure documented.

---

## TODO-513: Signed Release, Install, Upgrade, and Rollback Proof

**Target:** Clean Linux VM (Debian Bookworm or Ubuntu 22.04+).
**Prerequisites:** Fresh VM with root access, no prior QuicFuscate install,
GitHub CLI (`gh`) configured to download release artifacts.

### Step 1 — Trigger a release build

```bash
# On local Mac:
gh workflow run release.yml
gh run watch <run-id>
# Download artifacts:
gh run download <run-id> -n quicfuscate-linux-binary -D /tmp/release/
gh run download <run-id> -n quicfuscate-checksums -D /tmp/release/
```

### Step 2 — Verify checksums and signature

```bash
cd /tmp/release/
sha256sum -c checksums-sha256.txt
# Expected: quicfuscate: OK

# If GPG signing was configured:
gpg --verify checksums-sha256.txt.sig checksums-sha256.txt
# Expected: Good signature from RELEASE_GPG_KEY_ID
```

### Step 3 — Transfer to clean VM and install

```bash
# Transfer artifacts to VM:
scp /tmp/release/quicfuscate /tmp/release/checksums-sha256.txt \
    /tmp/release/install-server-linux.sh user@vm:/tmp/

# On the clean VM:
ssh user@vm
cd /tmp
chmod +x install-server-linux.sh
sudo ./install-server-linux.sh
# Expected: exits 0, creates quicfuscate user, installs binary + config + service
```

### Step 4 — Verify service lifecycle

```bash
sudo systemctl start quicfuscate
sudo systemctl is-active quicfuscate
# Expected: active

sudo systemctl status quicfuscate
# Expected: active (running), no errors in journalctl

sudo systemctl stop quicfuscate
sudo systemctl is-active quicfuscate
# Expected: inactive

sudo systemctl restart quicfuscate
sudo systemctl is-active quicfuscate
# Expected: active
```

### Step 5 — Upgrade proof

```bash
# Simulate upgrade: install a new version over the old one
sudo ./install-server-linux.sh  # re-run with new binary
# Expected: binary replaced, config and QKey registry preserved
sudo systemctl restart quicfuscate
# Verify config intact:
sudo cat /etc/quicfuscate/quicfuscate.toml | grep -c "Wired"
# Verify QKey registry intact:
sudo ls -la /var/lib/quicfuscate/qkeys.json
```

### Step 6 — Rollback proof

```bash
# Save current binary, restore previous version
sudo cp /usr/local/bin/quicfuscate /usr/local/bin/quicfuscate.new
sudo cp /tmp/quicfuscate.previous /usr/local/bin/quicfuscate
sudo systemctl restart quicfuscate
sudo systemctl is-active quicfuscate
# Expected: active with previous version

# Restore new version
sudo cp /usr/local/bin/quicfuscate.new /usr/local/bin/quicfuscate
sudo systemctl restart quicfuscate
```

### Step 7 — Uninstall proof

```bash
sudo systemctl stop quicfuscate
sudo systemctl disable quicfuscate
sudo rm /usr/local/bin/quicfuscate
sudo rm /etc/systemd/system/quicfuscate.service
sudo systemctl daemon-reload
# Verify state archived or removed:
ls -la /var/lib/quicfuscate/  # should be preserved or explicitly archived
ls -la /etc/quicfuscate/      # should be preserved or explicitly archived
```

### Step 8 — Close TODO-513

Update `docs/todo/todo-513-*.md`:
- Change `status: OPEN` to `status: DONE` in frontmatter.
- Append `## Execution Evidence` with: VM OS/version, commit SHA, checksum verification output, install/upgrade/rollback/uninstall results, config/QKey preservation proof.
- Update `docs/todo.md` row for TODO-513 to `**DONE**`.

---

## Post-Closure Checklist

After all three TODOs are closed:
1. Update `docs/todo.md` closure rule: remove the `OPEN (prepared)` carve-out
   since no OPEN items remain.
2. Update `docs/DOCUMENTATION.md` "Release Scope" and "Current Release
   Checkpoint" sections with the verified release readiness level.
3. Run `bash scripts/tests/audits/audit-todo-consistency.sh` — must be 0 violations.
4. Commit and push doc updates.
5. The repository can now honestly claim production-ready status.
