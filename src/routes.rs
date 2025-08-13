use crate::{ARGS, AppState};
use crate::totp::*;
use crate::session::*;

use axum::{extract::{Form, State}, http::{HeaderMap, StatusCode}, response::IntoResponse};
use axum_extra::extract::cookie::{CookieJar, Cookie};
use chrono::Utc;
use cookie::time::OffsetDateTime;
use pam::Client;
use serde::Deserialize;
use uuid::Uuid;

/// Login form definition
#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    totp: String,
}

/// Internal session / auth check, used by nginx
pub async fn check_session(
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
pub async fn handle_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Result<(CookieJar, &'static str), (StatusCode, &'static str)> {

    // Validate input data: username
    let username = form.username.trim();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username cannot be empty"));
    }

    // TOTP format
    let code = match form.totp.trim().parse::<u32>() {
        Ok(c) => c,
        Err(_) => { return Err((StatusCode::BAD_REQUEST, "Invalid TOTP format")); }
    };

    // Username is not in TOTP shadow file
    if !state.totp_cache.read().await.contains_key(username) {
        println!("Login denied: User {} not in TOTP shadow file", username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid username, password or TOTP"));
    }

    // Create PAM-Client
    let mut client = match Client::with_password("nginx-proxy-auth") {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to initialize PAM client: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Authentication service error"));
        }
    };

    // 1. Check password
    client.conversation_mut().set_credentials(username, &form.password);
    if client.authenticate().is_err() {
        println!("Login denied: Wrong password for user {}", username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid username, password or TOTP"));
    }

    // 2. Verify TOTP
    if !verify_totp(username, code, &state.totp_cache).await {
        println!("Login denied: Invalid TOTP for {}", username);
        return Err((StatusCode::UNAUTHORIZED, "Invalid username, password or TOTP"));
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
                .same_site(cookie::SameSite::Lax)
                .expires(offset_dt)
        ),
        "Login successful"
    ))
}

/// External logout, used by the browser via nginx reverse proxy
pub async fn handle_logout(
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
