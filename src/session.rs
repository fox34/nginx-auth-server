use crate::ARGS;

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::{Duration as TokioDuration, interval};

/// Session definition
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub username: String,
    pub expires_at: DateTime<Utc>,
}

/// Session storage
pub type SessionStore = Arc<RwLock<HashMap<String, SessionData>>>; // session_id -> SessionData

/// Helper function: Validate and parse session lifetime to duration
pub fn parse_session_lifetime(input: &str) -> Result<Duration, String> {
    let suffix = input.chars().last().ok_or("Empty value")?;
    let number = &input[..input.len() - 1];
    let amount: i64 = number.parse().map_err(|_| "Not a valid number")?;

    let duration = match suffix {
        'm' => Duration::minutes(amount),
        'h' => Duration::hours(amount),
        'd' => Duration::days(amount),
        'y' => Duration::days(amount * 365), // One year = 365 days
        _ => return Err("Invalid format for --session-lifetime. Valid: <number><m|h|d|y> (e.g. 30m, 2h, 7d, 1y)".into()),
    };

    Ok(duration)
}

/// Helper function: Load sessions from file
pub fn load_sessions_from_file() -> Result<HashMap<String, SessionData>, std::io::Error> {

    // Session storage enabled
    if let Some(session_file) = &ARGS.session_file {
        println!("- Using session file for persistent storage: '{}'", session_file);

        let path = Path::new(session_file);
        if path.try_exists()? {
            println!("  Loading sessions from persistent storage...");
            let content = fs::read_to_string(path)?;
            let all: HashMap<String, SessionData> = serde_json::from_str(&content).unwrap_or_default();

            // Only load valid sessions
            let now = Utc::now();
            let res: HashMap<String, SessionData> = all
                .into_iter()
                .filter(|(_, s)| s.expires_at > now)
                .collect();

            println!("  Loaded {} sessions.", res.len());
            return Ok(res)
        }
    }

    // Session storage not enabled or file not found
    Ok(HashMap::new())
}

/// Helper function: Persist sessions to file
pub async fn save_sessions_to_file(sessions: &SessionStore) -> Result<(), std::io::Error>  {

    // Session storage enabled
    if let Some(session_file) = &ARGS.session_file {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(session_file)?;

        let session_guard = sessions.write().await;
        let json = serde_json::to_string(&*session_guard)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        drop(session_guard);

        let mut writer = std::io::BufWriter::new(file);
        writer.write_all(json.as_bytes())?;
        writer.flush()?;

        if ARGS.verbose {
            println!("Sessions written to persistent storage: '{}'", session_file);
        }
    }

    Ok(())
}

/// Helper function: Cleanup expired sessions
pub async fn cleanup_expired_sessions(sessions: SessionStore) {

    // Only once every hour, since sessions usually have a long lifetime
    let mut ticker = interval(TokioDuration::from_secs(60 * 60));

    loop {
        ticker.tick().await;

        if ARGS.verbose {
            println!("Cleaning up expired sessions...");
        }

        let now = Utc::now();

        let mut session_guard = sessions.write().await;
        let session_count_before = session_guard.len();
        session_guard.retain(|_, s| s.expires_at > now);
        let session_count_after = session_guard.len();
        drop(session_guard);

        save_sessions_to_file(&sessions)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Error saving sessions during cleanup: {}", e);
            });

        if session_count_before != session_count_after && ARGS.verbose {
            println!("Cleaned up {} expired sessions", session_count_before - session_count_after);
        }
    }
}
