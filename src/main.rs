mod totp;
mod session;
mod routes;

use crate::totp::*;
use crate::session::*;
use crate::routes::*;

use axum::{routing::{get, post}, Router};
use chrono::Duration;
use clap::Parser;
use once_cell::sync::Lazy;
use std::{fs::File, path::Path, sync::Arc};
use tokio::sync::RwLock;

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

    println!("Starting nginx-auth-server v{} on {} using shadow file '{}'.", env!("CARGO_PKG_VERSION"), ARGS.listen, ARGS.shadow_file);
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
