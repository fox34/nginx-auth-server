use axum::{
    extract::{Form, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use cookie::time::OffsetDateTime;
use once_cell::sync::Lazy;
use otpauth::TOTP;
use pam::Client;
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{sync::RwLock, time::{interval, Duration as TokioDuration}};
use uuid::Uuid;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Listening address, e.g. 127.0.0.1:1337
    #[arg(long)]
    listen: String,

    /// Path of TOTP shadow file, e.g. /etc/shadow_totp
    #[arg(long)]
    shadow_file: String,

    /// Session persistence file, e.g. /tmp/nginx-auth-server.sessions
    #[arg(long)]
    session_file: Option<String>,

    /// Session lifetime. Valid: <number><m|h|d|y> (e.g. 30m, 2h, 7d, 1y)
    #[arg(long, value_parser = parse_session_lifetime, default_value = "1y")]
    session_lifetime: Duration,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}
static ARGS: Lazy<Args> = Lazy::new(Args::parse);

/// Login form definition
#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    totp: String,
}

/// Session definition
#[derive(Debug, Serialize, Deserialize, Clone)]
struct SessionData {
    username: String,
    expires_at: DateTime<Utc>,
}

/// Session and TOTP shadow file storage
type SessionStore = Arc<RwLock<HashMap<String, SessionData>>>; // session_id -> SessionData
type TotpShadowCache = Arc<RwLock<HashMap<String, String>>>;

/// Application state
#[derive(Clone)]
struct AppState {
    sessions: SessionStore,
    totp_cache: TotpShadowCache,
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Check if provided shadow file exists and is readable
    let shadow_path = Path::new(&ARGS.shadow_file);
    if !shadow_path.try_exists().unwrap() {
        eprintln!("Shadow file '{}' does not exist.", &ARGS.shadow_file);
        std::process::exit(1);
    }

    if let Err(e) = File::open(&ARGS.shadow_file).map(|_| ()) {
        eprintln!("Shadow file '{}' is not readable: {}", &ARGS.shadow_file, e);
        std::process::exit(1);
    }

    println!("Starting nginx-auth-proxy on {} using shadow file '{}'.", ARGS.listen, ARGS.shadow_file);
    println!("- Session lifetime: {}", ARGS.session_lifetime);

    // Load persistent sessions, if enabled
    let sessions: SessionStore = Arc::new(RwLock::new(load_sessions_from_file()?));

    // Initialize and load TOTP shadow cache
    let totp_cache = Arc::new(RwLock::new(load_totp_shadow_cache()?));

    // Create application state
    let app_state = AppState {
        sessions: Arc::clone(&sessions),
        totp_cache: Arc::clone(&totp_cache),
    };

    // Periodically cleanup sessions and reload TOTP shadow cache
    tokio::spawn(cleanup_expired_sessions(Arc::clone(&sessions)));
    tokio::spawn(reload_totp_cache_periodically(Arc::clone(&totp_cache)));

    // Create routes
    let app = Router::new()
        .route("/auth/check", get(check_session))
        .route("/auth/login", post(handle_login))
        .route("/auth/logout", get(handle_logout))
        .with_state(app_state.into())
    ;
    
    let listener = tokio::net::TcpListener::bind(&ARGS.listen).await?;
    println!("Waiting for connections...");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Internal session / auth check, used by nginx
async fn check_session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse
{
    // Session cookie provided
    if let Some(id) = jar.get("nginx-auth") {

        let session_guard = state.sessions.read().await;

        // Session found
        if let Some(session_data) = session_guard.get(id.value()) {

            // Session is valid
            if session_data.expires_at > Utc::now() {
                if ARGS.verbose {
                    println!("Session {} of user {} found, expires: {} UTC", id.value(), session_data.username, session_data.expires_at.format("%Y-%m-%d %H:%M:%S"));
                }
                let mut headers = HeaderMap::new();
                headers.insert("Remote-User", session_data.username.parse().unwrap());
                return (StatusCode::OK, headers).into_response();

            } else {

                // Session expired, remove from store
                println!("Session {} of user {} expired at {} UTC, removing", id.value(), session_data.username, session_data.expires_at.format("%Y-%m-%d %H:%M:%S"));
                drop(session_guard);
                state.sessions.write().await.remove(id.value());
                save_sessions_to_file(&state.sessions)
                    .await
                    .unwrap_or_else(|e| eprintln!("Error saving sessions: {}", e));

            }
        } else if ARGS.verbose {
            println!("Session {} is invalid or already expired", id.value())
        }

        // Remove invalid cookie
        return (
            StatusCode::UNAUTHORIZED,
            jar.remove(
                Cookie::build("nginx-auth")
                    .path("/")
                    .http_only(true)
                    .same_site(cookie::SameSite::Strict)
            )
        ).into_response()
    }

    // No session cookie provided
    StatusCode::UNAUTHORIZED.into_response()
}

/// External login, used by the browser via nginx reverse proxy
async fn handle_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, &'static str), (StatusCode, &'static str)> {

    // Validate username
    let username = form.username.trim();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username cannot be empty"));
    }

    // Validate TOTP format
    let code = match form.totp.trim().parse::<u32>() {
        Ok(c) => c,
        Err(_) => { return Err((StatusCode::BAD_REQUEST, "Invalid TOTP format")); }
    };

    // 1. First verify TOTP (to check if user is in TOTP shadow file)
    if !verify_totp(username, code, &state.totp_cache).await {
        println!("Login denied: Invalid TOTP for {}", username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid TOTP"));
    }

    // Create PAM-Client
    let mut client = match Client::with_password("nginx-proxy-auth") {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to initialize PAM client: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Authentication service error"));
        }
    };

    // 2. Then check against system users (to prevent information leakage about system users not in TOTP file)
    client.conversation_mut().set_credentials(username, &form.password);
    if client.authenticate().is_err() {
        println!("Login denied: Username {} or password invalid", username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid username or password"));
    }

    // Create session
    let session_id = Uuid::new_v4().to_string();
    let expires = Utc::now() + ARGS.session_lifetime;
    state.sessions.write().await.insert(
        session_id.clone(),
        SessionData {
            username: username.to_string(),
            expires_at: expires,
        },
    );

    // Persist sessions in file, if enabled
    save_sessions_to_file(&state.sessions)
        .await
        .unwrap_or_else(|e| eprintln!("Error saving sessions: {}", e));

    println!("Login successful: {}", username);
    let offset_dt = OffsetDateTime::from_unix_timestamp(expires.timestamp())
        .unwrap_or_else(|_| OffsetDateTime::now_utc());

    Ok((
        jar.add(
            Cookie::build(("nginx-auth", session_id))
                .path("/")
                .http_only(true)
                .same_site(cookie::SameSite::Strict)
                .expires(offset_dt)
        ),
        "Login successful"
    ))
}

/// External logout, used by the browser via nginx reverse proxy
async fn handle_logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    // Session cookie provided
    if let Some(id) = jar.get("nginx-auth") {

        let mut session_guard = state.sessions.write().await;

        // Session found
        if let Some(session_data) = session_guard.get(id.value()) {
            println!("User {} logged out, removing session {}", session_data.username, id.value());
            session_guard.remove(id.value());
            drop(session_guard);
            save_sessions_to_file(&state.sessions)
                .await
                .unwrap_or_else(|e| eprintln!("Error saving sessions: {}", e));
        }

        // Remove cookie
        return (
            StatusCode::OK,
            jar.remove(
                Cookie::build("nginx-auth")
                    .path("/")
                    .http_only(true)
                    .same_site(cookie::SameSite::Strict)
            )
        ).into_response();
    }

    StatusCode::OK.into_response()
}

/// Helper function: Verify TOTP code against the cached shadow file
async fn verify_totp(
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
fn load_totp_shadow_cache() -> Result<HashMap<String, String>, std::io::Error> {
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
async fn reload_totp_cache_periodically(totp_cache: TotpShadowCache) {
    let mut ticker = interval(TokioDuration::from_secs(5 * 60)); // Every 5 minutes

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

/// Helper function: Validate and parse session lifetime to duration
fn parse_session_lifetime(input: &str) -> Result<Duration, String> {
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
fn load_sessions_from_file() -> Result<HashMap<String, SessionData>, std::io::Error> {

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
async fn save_sessions_to_file(sessions: &SessionStore) -> Result<(), std::io::Error>  {

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
async fn cleanup_expired_sessions(sessions: SessionStore) {

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
