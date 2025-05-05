use axum::{body::Body, extract::{Form, State}, response::Response, routing::{get, post}, Router, http::StatusCode};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use clap::Parser;
use cookie::time::{Duration, OffsetDateTime};
use serde::Deserialize;
use std::{collections::HashMap, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};
use pam::Client;
use once_cell::sync::Lazy;
use otpauth::TOTP;
use uuid::Uuid;
use std::fs;
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Listening address, e.g. 127.0.0.1:1337
    #[arg(long)]
    listen: String,

    /// Path of TOTP shadow file
    #[arg(long)]
    shadow_file: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Optional path of persistent session file
    #[arg(long)]
    session_file: Option<String>,
}
static ARGS: Lazy<Args> = Lazy::new(Args::parse);

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    totp: String,
}

type SessionStore = Arc<Mutex<HashMap<String, String>>>; // session_id -> username

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

    // Load persistent sessions
    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));
    if let Some(session_file) = &ARGS.session_file {
        println!("- Using session file for persistent storage: '{}'", session_file);

        if fs::exists(session_file).unwrap() {
            println!("  Loading sessions from persistent storage...");
            let persistent_sessions = fs::read_to_string(session_file).unwrap();

            for (_, line) in persistent_sessions.lines().enumerate() {
                if line.is_empty() {
                    continue
                }
                let mut parts = line.splitn(2, ',');
                let session_id = parts.next().unwrap_or("").trim();
                let username = parts.next().unwrap_or("").trim();

                if !session_id.is_empty() && !username.is_empty() {
                    sessions.lock().unwrap().insert(session_id.to_string(), username.to_string());
                    if ARGS.verbose {
                        println!("  Loaded session {} → {}", session_id.to_string(), username.to_string());
                    }
                }

                // TODO: Expiration
            }
        }
    }

    let app = Router::new()
        .route("/auth/check", get(check_login))
        .route("/auth/login", post(handle_login))
        .with_state(sessions.into())
    ;
    
    let listener = tokio::net::TcpListener::bind(&ARGS.listen).await.unwrap();
    println!("Waiting for connections...");
    axum::serve(listener, app).await.unwrap();
}

/// Internal session / auth check, used by nginx
async fn check_login(
    State(sessions): State<Arc<SessionStore>>,
    jar: CookieJar,
) -> Response
{
    // Session cookie provided
    if let Some(id) = jar.get("nginx-auth") {

        // Look up session
        let sessions = sessions.lock().unwrap();
        if let Some(username) = sessions.get(id.value()) {
            if ARGS.verbose {
                println!("Valid session found: {} → {}", id.value(), username);
            }

            return Response::builder()
                .status(StatusCode::OK)
                .header("Remote-User", username)
                .body(Body::from(""))
                .unwrap()
            ;
        }

        if ARGS.verbose {
            println!("Provided session is invalid: {}", id.value())
        }
    } else if ARGS.verbose {
        println!("Session cookie not provided");
    }

    Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("")).unwrap()
}

/// External login, used by the browser
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
        
        // Create and persist session
        let session_id = Uuid::new_v4().to_string();
        sessions.lock().unwrap().insert(session_id.clone(), form.username.clone());

        if let Some(session_file) = &ARGS.session_file {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .mode(0o600)
                .open(session_file)
                .unwrap();

            if let Err(e) =  writeln!(file, "{},{}", session_id.clone(), form.username.clone()) {
                eprintln!("Couldn't write to session file: {}", e);
            } else if ARGS.verbose {
                println!("Session written to persistent storage: '{}'", session_file);
            }
        }

        println!("Login successful: {}", &form.username);
        let mut expires = OffsetDateTime::now_utc();
        expires += Duration::weeks(52);
        return Ok((
            jar.add(Cookie::build(("nginx-auth", session_id)).path("/").http_only(true).expires(expires)),
            "Login successful"
        ));
    }
    
    println!("Login denied: Missing TOTP {}", &form.username);
    Err((StatusCode::UNAUTHORIZED, "TOTP missing"))
}
