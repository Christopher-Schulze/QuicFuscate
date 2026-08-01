use clap::{Parser, Subcommand};
use quicfuscate::implementations::server::{BlacklistSync, GeoIpBlocker, GeoIpConfig};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "qf-ddos-policy-probe")]
#[command(about = "Prove real GeoIP and HTTPS blacklist policy data paths")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Geoip {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        blocked_country: String,
        #[arg(long, required = true)]
        expect_blocked: Vec<IpAddr>,
        #[arg(long, required = true)]
        expect_allowed: Vec<IpAddr>,
    },
    Blacklist {
        #[arg(long)]
        sync_url: String,
        #[arg(long)]
        failure_url: String,
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        ca_certificate: PathBuf,
        #[arg(long)]
        expected_entries: usize,
        #[arg(long, required = true)]
        expect_blocked: Vec<IpAddr>,
        #[arg(long, required = true)]
        expect_allowed: Vec<IpAddr>,
        #[arg(long, default_value_t = 2)]
        request_timeout_secs: u64,
        #[arg(long, default_value_t = 65_536)]
        max_body_bytes: usize,
        #[arg(long, default_value_t = 1_024)]
        max_entries: usize,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::Geoip { database, blocked_country, expect_blocked, expect_allowed } => {
            run_geoip(database, blocked_country, expect_blocked, expect_allowed)
        }
        Command::Blacklist {
            sync_url,
            failure_url,
            cache,
            ca_certificate,
            expected_entries,
            expect_blocked,
            expect_allowed,
            request_timeout_secs,
            max_body_bytes,
            max_entries,
        } => {
            run_blacklist(
                sync_url,
                failure_url,
                cache,
                ca_certificate,
                expected_entries,
                expect_blocked,
                expect_allowed,
                request_timeout_secs,
                max_body_bytes,
                max_entries,
            )
            .await
        }
    }
}

fn run_geoip(
    database: PathBuf,
    blocked_country: String,
    expect_blocked: Vec<IpAddr>,
    expect_allowed: Vec<IpAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let blocked_country = blocked_country.trim().to_ascii_uppercase();
    let blocker = GeoIpBlocker::try_new(GeoIpConfig {
        db_path: Some(database.clone()),
        blocked_countries: HashSet::from([blocked_country.clone()]),
    })?;
    if !blocker.is_enabled() {
        return Err("GeoIP blocker did not enable with a database and country policy".into());
    }
    assert_ip_policy(&expect_blocked, true, |ip| blocker.is_blocked(ip), "GeoIP")?;
    assert_ip_policy(&expect_allowed, false, |ip| blocker.is_blocked(ip), "GeoIP")?;

    println!(
        "{}",
        serde_json::json!({
            "result": "pass",
            "policy": "geoip",
            "status": blocker.status().as_str(),
            "database": database,
            "blocked_country": blocked_country,
            "blocked_addresses": expect_blocked,
            "allowed_addresses": expect_allowed,
        })
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_blacklist(
    sync_url: String,
    failure_url: String,
    cache: PathBuf,
    ca_certificate: PathBuf,
    expected_entries: usize,
    expect_blocked: Vec<IpAddr>,
    expect_allowed: Vec<IpAddr>,
    request_timeout_secs: u64,
    max_body_bytes: usize,
    max_entries: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if expected_entries == 0 {
        return Err("--expected-entries must be greater than zero".into());
    }
    if request_timeout_secs == 0 || max_body_bytes == 0 || max_entries == 0 {
        return Err("blacklist timeout and bounds must be greater than zero".into());
    }
    if cache.exists() {
        return Err(format!("refusing existing blacklist cache: {}", cache.display()).into());
    }
    ensure_regular_nonempty_file(&ca_certificate)?;
    let cache_parent = cache.parent().unwrap_or_else(|| Path::new("."));
    if !cache_parent.is_dir() {
        return Err(
            format!("blacklist cache parent does not exist: {}", cache_parent.display()).into()
        );
    }

    let timeout = Duration::from_secs(request_timeout_secs);
    let synced = BlacklistSync::new_bounded_with_ca(
        Duration::from_secs(60),
        Some(sync_url.clone()),
        Duration::from_secs(60),
        timeout,
        max_body_bytes,
        max_entries,
        Some(cache.clone()),
        Some(ca_certificate),
    )?;
    let synced_entries = synced.sync().await?;
    if synced_entries != expected_entries {
        return Err(format!(
            "blacklist sync loaded {synced_entries} entries, expected {expected_entries}"
        )
        .into());
    }
    assert_ip_policy(&expect_blocked, true, |ip| synced.is_blocked(ip), "blacklist sync")?;
    assert_ip_policy(&expect_allowed, false, |ip| synced.is_blocked(ip), "blacklist sync")?;
    ensure_regular_nonempty_file(&cache)?;

    let reloaded = BlacklistSync::new_bounded(
        Duration::from_secs(60),
        Some(failure_url.clone()),
        Duration::from_secs(60),
        timeout,
        max_body_bytes,
        max_entries,
        Some(cache.clone()),
    )?;
    if reloaded.len() != expected_entries {
        return Err(format!(
            "blacklist cache restart loaded {} entries, expected {expected_entries}",
            reloaded.len()
        )
        .into());
    }
    let refresh_error =
        reloaded.sync().await.expect_err("unreachable refresh endpoint unexpectedly succeeded");
    if reloaded.len() != expected_entries {
        return Err("failed blacklist refresh replaced the last-known-good entries".into());
    }
    assert_ip_policy(
        &expect_blocked,
        true,
        |ip| reloaded.is_blocked(ip),
        "blacklist last-known-good",
    )?;
    assert_ip_policy(
        &expect_allowed,
        false,
        |ip| reloaded.is_blocked(ip),
        "blacklist last-known-good",
    )?;

    println!(
        "{}",
        serde_json::json!({
            "result": "pass",
            "policy": "blacklist",
            "sync_url": sync_url,
            "cache": cache,
            "synced_entries": synced_entries,
            "restart_entries": reloaded.len(),
            "failed_refresh_preserved_last_known_good": true,
            "failed_refresh_error": refresh_error.to_string(),
            "blocked_addresses": expect_blocked,
            "allowed_addresses": expect_allowed,
        })
    );
    Ok(())
}

fn ensure_regular_nonempty_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("expected a non-empty regular file: {}", path.display()).into());
    }
    Ok(())
}

fn assert_ip_policy(
    addresses: &[IpAddr],
    expected: bool,
    evaluate: impl Fn(IpAddr) -> bool,
    policy: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for &address in addresses {
        let actual = evaluate(address);
        if actual != expected {
            return Err(format!(
                "{policy} decision mismatch for {address}: expected blocked={expected}, got {actual}"
            )
            .into());
        }
    }
    Ok(())
}
