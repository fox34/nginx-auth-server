use axum::{extract::{Form, State}, http::HeaderMap, response::IntoResponse, routing::{get, post}, Router, http::StatusCode};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use cookie::time::OffsetDateTime;
use once_cell::sync::Lazy;
use otpauth::TOTP;
use pam::Client;
use serde::{Serialize, Deserialize};
use std::{collections::HashMap, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};
use std::fs;
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;
use tokio::time::{interval, Duration as TokioDuration};
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

/// Session storage
type SessionStore = Arc<Mutex<HashMap<String, SessionData>>>; // session_id -> SessionData

/// Main entry point
#[tokio::main]
async fn main() {

    // Check if provided shadow file exists
    if !fs::exists(&ARGS.shadow_file).unwrap() {
        eprintln!("shadow file '{}' does not exist.", &ARGS.shadow_file);
        std::process::exit(1);
    }

    // Check if provided shadow file is readable by the current user
    if let Err(e) = fs::File::open(&ARGS.shadow_file).map(|_| ()) {
        eprintln!("shadow file '{}' ist not readable: {}", &ARGS.shadow_file, e);
        std::process::exit(1);
    }

    println!("Starting nginx-auth-proxy on {} using shadow file '{}'.", ARGS.listen, ARGS.shadow_file);
    println!("- Session lifetime: {}", ARGS.session_lifetime);

    // Load persistent sessions, if enabled
    let sessions: SessionStore = Arc::new(Mutex::new(load_sessions_from_file()));

    // Periodically cleanup sessions
    tokio::spawn(cleanup_expired_sessions(Arc::clone(&sessions)));

    // Create routes
    let app = Router::new()
        .route("/auth/check", get(check_session))
        .route("/auth/login", post(handle_login))
        .route("/auth/logout", get(handle_logout))
        .with_state(sessions.into())
    ;
    
    let listener = tokio::net::TcpListener::bind(&ARGS.listen).await.unwrap();
    println!("Waiting for connections...");
    axum::serve(listener, app).await.unwrap();
}

/// Internal session / auth check, used by nginx
async fn check_session(
    State(sessions): State<Arc<SessionStore>>,
    jar: CookieJar,
) -> impl IntoResponse
{
    // Session cookie provided
    if let Some(id) = jar.get("nginx-auth") {

        let mut session_guard = sessions.lock().unwrap();

        // Session found
        if let Some(session_data) = session_guard.get(id.value()) {

            // Session is valid
            if session_data.expires_at > Utc::now() {
                if ARGS.verbose {
                    println!("Session {} of user {} found, expires: {} UTC", id.value(), session_data.username.to_string(), session_data.expires_at.format("%Y-%m-%d %H:%M:%S"));
                }
                let mut headers = HeaderMap::new();
                headers.insert("Remote-User", session_data.username.to_string().parse().unwrap());
                return (StatusCode::OK, headers).into_response();
            } else {
                if ARGS.verbose {
                    println!("Session {} of user {} expired at {} UTC, removing", id.value(), session_data.username.to_string(), session_data.expires_at.format("%Y-%m-%d %H:%M:%S"));
                }
                session_guard.remove(id.value());
                drop(session_guard);
                save_sessions_to_file(&sessions);
            }
        } else if ARGS.verbose {
            println!("Session {} is invalid or expired", id.value())
        }

        // Remove invalid cookie
        return (StatusCode::UNAUTHORIZED, jar.remove("nginx-auth")).into_response()
    }

    // No session cookie provided
    StatusCode::UNAUTHORIZED.into_response()
}

/// External login, used by the browser via nginx reverse proxy
async fn handle_login(
    State(sessions): State<Arc<SessionStore>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, &'static str), (StatusCode, &'static str)> {

    // Create PAM-Client
    let mut client = Client::with_password("nginx-proxy-auth")
        .expect("Failed to init PAM client.");
    
    // Check login data
    client.conversation_mut().set_credentials(&form.username, &form.password);
    if client.authenticate().is_err() {
        println!("Login denied: Username {} or password invalid", &form.username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid username or password"));
    }
    
    // Check TOTP
    let totp_file = fs::read_to_string(&ARGS.shadow_file).unwrap();
    let mut totp_map = HashMap::new();
    
    for (_, line) in totp_file.lines().enumerate() {
        if line.is_empty() {
            continue
        }
        let mut parts = line.splitn(2, ',');
        let username = parts.next().unwrap_or("").trim();
        let secret = parts.next().unwrap_or("").trim();

        if !username.is_empty() && !secret.is_empty() {
            totp_map.insert(username.to_string(), secret.to_string());
        }
    }
    
    let totp_map = Arc::new(totp_map);

    if let Some(user_entry) = totp_map.get(&form.username) {
        let code: u32 = form.totp.parse().unwrap_or(0);
        let totp = TOTP::from_base32(user_entry).unwrap();
        if !totp.verify(code, 30, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) {
            println!("Login denied: Invalid TOTP for {}", &form.username);
            return Err((StatusCode::UNAUTHORIZED, "Invalid TOTP"))
        }
        
        // Create session
        let session_id = Uuid::new_v4().to_string();
        let expires = Utc::now() + ARGS.session_lifetime;
        sessions.lock().unwrap().insert(session_id.clone(), SessionData { username: form.username.clone(), expires_at: expires });

        // Persist sessions in file, if enabled
        save_sessions_to_file(&sessions);

        println!("Login successful: {}", &form.username);
        let offset_dt = OffsetDateTime::from_unix_timestamp(expires.timestamp())
            .expect("valid timestamp");
        return Ok((
            jar.add(Cookie::build(("nginx-auth", session_id)).path("/").http_only(true).expires(offset_dt)),
            "Login successful"
        ));
    }
    
    println!("Login denied: Missing TOTP {}", &form.username);
    Err((StatusCode::UNAUTHORIZED, "TOTP missing"))
}

/// External logout, used by the browser via nginx reverse proxy
async fn handle_logout(
    State(sessions): State<Arc<SessionStore>>,
    jar: CookieJar,
) -> impl IntoResponse
{
    // Session cookie provided
    if let Some(id) = jar.get("nginx-auth") {

        // Session found
        if let Some(session_data) = sessions.lock().unwrap().get(id.value()) {
            println!("User {} logout, removing session {}", id.value(), session_data.username.to_string());
            sessions.lock().unwrap().remove(id.value());
        }

        // Remove cookie
        return (StatusCode::OK, jar.remove("nginx-auth")).into_response()
    }

    StatusCode::OK.into_response()
}

/// Helper function: Validate and parse session lifetime to duration
fn parse_session_lifetime(input: &str) -> Result<Duration, String> {
    let suffix = input.chars().last().ok_or("Leerer Wert")?;
    let number = &input[..input.len() - 1];
    let amount: i64 = number.parse().map_err(|_| "Keine gültige Zahl")?;

    let duration = match suffix {
        'm' => Duration::minutes(amount),
        'h' => Duration::hours(amount),
        'd' => Duration::days(amount),
        'y' => Duration::days(amount * 365), // One year = 365 days
        _ => return Err("Invalid format for --session-lifetime. Valid: <number><m|h|d|y> (e.g. 30m, 2h, 7d, 1y)".into()),
    };

    Ok(duration)
}

/// Helper function: Load sesssions from file
fn load_sessions_from_file() -> HashMap<String, SessionData> {

    // Session storage enabled
    if let Some(session_file) = &ARGS.session_file {
        println!("- Using session file for persistent storage: '{}'", session_file);

        if fs::exists(session_file).unwrap() {
            println!("  Loading sessions from persistent storage...");
            let content = fs::read_to_string(session_file).unwrap_or_default();
            let all: HashMap<String, SessionData> = serde_json::from_str(&content).unwrap_or_default();

            // Only load valid sessions
            let now = Utc::now();
            let res: HashMap<String, SessionData> = all.into_iter()
                .filter(|(_, s)| s.expires_at > now)
                .collect();

            println!("  Loaded {} sessions.", res.len());
            return res
        }
    }

    // Session storage not enabled or file not found
    HashMap::new()
}

/// Helper function: Persist sessions to file
fn save_sessions_to_file(sessions: &SessionStore) {
    if let Some(session_file) = &ARGS.session_file {
        let res = fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(session_file);
        if let Ok(mut file) = res {
            let session_guard = sessions.lock().unwrap();
            let json = serde_json::to_string_pretty(&*session_guard).unwrap();
            file.write_all(json.as_bytes()).unwrap();
            drop(session_guard);
            if ARGS.verbose {
                println!("Sessions written to persistent storage: '{}'", session_file);
            }
        } else {
            eprintln!("Could not write sessions to file '{}': {}", session_file, res.unwrap_err());
        }
    }
}

/// Helper function: Cleanup expired sessions
async fn cleanup_expired_sessions(sessions: SessionStore) {
    let mut ticker = interval(TokioDuration::from_secs(60 * 60));

    loop {
        ticker.tick().await;
        let now = Utc::now();

        let mut session_guard = sessions.lock().unwrap();
        let before = session_guard.len();
        session_guard.retain(|_, s| s.expires_at > now);
        let after = session_guard.len();
        drop(session_guard);

        save_sessions_to_file(&sessions);

        if before != after && ARGS.verbose {
            println!("Cleaned up {} expired sessions", before - after);
        }
    }
}
