use axum::{body::Body, extract::{Form, State}, response::Response, routing::{get, post}, Router, http::StatusCode};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use cookie::time::{Duration, OffsetDateTime};
use serde::Deserialize;
use std::{collections::HashMap, sync::{Arc, Mutex}, time::{SystemTime, UNIX_EPOCH}};
use pam::Client;
use otpauth::TOTP;
use uuid::Uuid;
use std::fs;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    totp: String,
}

type SessionStore = Arc<Mutex<HashMap<String, String>>>; // session_id -> username

#[tokio::main]
async fn main() {
    println!("Starting nginx-auth-proxy...");

    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));
    
    let app = Router::new()
        .route("/auth/check", get(check_login))
        .route("/auth/login", post(handle_login))
        .with_state(sessions.into())
    ;
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:1337").await.unwrap();
    println!("Waiting for connections at {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

// Internal session / auth check, used by nginx
async fn check_login(
    State(sessions): State<Arc<SessionStore>>,
    jar: CookieJar,
) -> Response
{
    // Very suboptimal response building code
    if let Some(id) = jar.get("nginx-auth") {
        let sessions = sessions.lock().unwrap();
        if let Some(username) = sessions.get(id.value()) {
            return Response::builder()
                .status(StatusCode::OK)
                .header("Remote-User", username)
                .body(Body::from(""))
                .unwrap()
            ;
        }
    }
    Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::from("")).unwrap()
}

// External login, used by the browser
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
    let totp_file = fs::read_to_string("/etc/shadow_totp").unwrap();
    let mut totp_map = HashMap::new();
    
    for (_, line) in totp_file.lines().enumerate() {
        if line.is_empty() {
            continue
        }
        let mut parts = line.splitn(2, ',');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();

        if !key.is_empty() && !value.is_empty() {
            totp_map.insert(key.to_string(), value.to_string());
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
        
        // Session erzeugen
        let session_id = Uuid::new_v4().to_string();
        sessions.lock().unwrap().insert(session_id.clone(), form.username.clone());

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
