use crate::ARGS;

use otpauth::TOTP;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufRead, BufReader},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{sync::RwLock, time::{Duration, interval}};

/// TOTP shadow file storage
pub type TotpShadowCache = Arc<RwLock<HashMap<String, String>>>;

/// Helper function: Verify TOTP code against the cached shadow file
pub async fn verify_totp(
    username: &str,
    code: u32,
    totp_cache: &TotpShadowCache,
) -> bool {
    if let Some(secret) = totp_cache.read().await.get(username) {
        if let Some(totp) = TOTP::from_base32(secret) {
            return totp.verify(
                code,
                30,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
        }
    }

    false
}

/// Helper function: Load TOTP shadow cache
pub fn load_totp_shadow_cache() -> Result<HashMap<String, String>, std::io::Error> {
    let mut cache = HashMap::new();
    let file = File::open(&ARGS.shadow_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Some((user, secret)) = line?.split_once(',') {
            cache.insert(user.trim().to_string(), secret.trim().to_string());
        }
    }

    println!("Loaded {} TOTP secrets from shadow file", cache.len());
    Ok(cache)
}

/// Helper function: Reload TOTP shadow cache periodically
pub async fn reload_totp_cache_periodically(totp_cache: TotpShadowCache) {
    let mut ticker = interval(Duration::from_secs(5 * 60)); // Every 5 minutes

    // Load initial modification time
    let mut last_modified = SystemTime::UNIX_EPOCH;
    if let Ok(metadata) = fs::metadata(&ARGS.shadow_file) {
        if let Ok(mtime) = metadata.modified() {
            last_modified = mtime;
        }
    }

    loop {
        ticker.tick().await;

        // Check file modification time
        let mut modified = SystemTime::UNIX_EPOCH;
        if let Ok(metadata) = fs::metadata(&ARGS.shadow_file) {
            if let Ok(mtime) = metadata.modified() {
                modified = mtime;
            }
        } else {
            eprintln!("Failed to get metadata of TOTP shadow file, force reload.");
        }

        // File not modified
        if modified == last_modified {
            if ARGS.verbose {
                println!("TOTP shadow cache not modified since last reload.");
            }
            continue;
        }

        if ARGS.verbose {
            println!("TOTP shadow cache file modified on disk, reloading...");
        }

        match load_totp_shadow_cache() {
            Ok(new_cache) => {
                let mut cache_guard = totp_cache.write().await;
                *cache_guard = new_cache;
                last_modified = modified;
                println!("Reloaded TOTP shadow cache: {} entries", cache_guard.len());
            },
            Err(e) => { eprintln!("Failed to reload TOTP shadow cache: {}", e); }
        }
    }
}
