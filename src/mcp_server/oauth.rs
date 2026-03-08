// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OAuth token management for the MCP Gateway.
//!
//! Handles Google OAuth flow delegation, per-user token storage,
//! PKCE validation, and automatic token refresh.

use std::collections::HashMap;

use sha2::Digest;
use tokio::sync::Mutex;

/// Default Google OAuth scopes requested during consent.
pub const DEFAULT_OAUTH_SCOPES: &str = "\
    openid email profile \
    https://www.googleapis.com/auth/drive \
    https://www.googleapis.com/auth/gmail.modify \
    https://www.googleapis.com/auth/calendar \
    https://www.googleapis.com/auth/spreadsheets \
    https://www.googleapis.com/auth/documents \
    https://www.googleapis.com/auth/presentations \
    https://www.googleapis.com/auth/chat.messages \
    https://www.googleapis.com/auth/tasks";

/// Maximum number of entries in each HashMap to prevent memory exhaustion.
const MAX_BEARER_SESSIONS: usize = 100_000;
const MAX_PENDING_CODES: usize = 10_000;
const MAX_PENDING_AUTHS: usize = 10_000;
const MAX_REGISTERED_CLIENTS: usize = 10_000;

/// Bearer token lifetime in seconds (24 hours).
pub const BEARER_TOKEN_LIFETIME_SECS: i64 = 86400;

/// Authorization code TTL in seconds (10 minutes).
pub const AUTH_CODE_TTL_SECS: i64 = 600;

/// Pending auth TTL in seconds (15 minutes).
pub const PENDING_AUTH_TTL_SECS: i64 = 900;

/// OAuth configuration for the MCP Gateway.
#[derive(Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
    pub scopes: String,
}

// Phase 2-13: Redact client_secret in Debug output.
impl std::fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("base_url", &self.base_url)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Stored Google OAuth tokens for a user.
#[derive(Debug, Clone)]
pub struct GoogleTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when the access token expires.
    pub expires_at: Option<i64>,
}

impl GoogleTokens {
    /// Returns true if the token is expired or will expire within 60 seconds.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|ea| chrono::Utc::now().timestamp() + 60 >= ea)
            .unwrap_or(false)
    }
}

/// An authenticated user session backed by Google OAuth tokens.
#[derive(Debug, Clone)]
pub struct UserSession {
    #[allow(dead_code)] // Used in Phase 5 (permissions) and Phase 7 (logging)
    pub email: String,
    pub google_tokens: GoogleTokens,
    /// Unix timestamp when the bearer token expires.
    pub bearer_expires_at: i64,
}

/// State tracked between the `/authorize` redirect and the `/oauth/callback`.
#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub client_redirect_uri: String,
    pub client_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[allow(dead_code)] // Used for audit logging and future per-client rate limiting
    pub client_id: String,
    pub created_at: i64,
}

/// State tracked between the `/oauth/callback` and the `POST /token` exchange.
#[derive(Debug, Clone)]
pub struct PendingCode {
    pub session: UserSession,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub created_at: i64,
}

/// A dynamically registered OAuth client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub client_id_issued_at: i64,
}

/// In-memory token and session store.
pub struct TokenStore {
    /// Our bearer token -> authenticated user session.
    pub bearer_sessions: HashMap<String, UserSession>,
    /// Our auth code -> pending code exchange data.
    pub pending_codes: HashMap<String, PendingCode>,
    /// Google OAuth state -> pending authorization data.
    pub pending_auths: HashMap<String, PendingAuth>,
    /// Dynamically registered clients.
    pub registered_clients: HashMap<String, RegisteredClient>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            bearer_sessions: HashMap::new(),
            pending_codes: HashMap::new(),
            pending_auths: HashMap::new(),
            registered_clients: HashMap::new(),
        }
    }

    /// Remove expired entries from all maps (lazy cleanup).
    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.pending_auths
            .retain(|_, v| now - v.created_at < PENDING_AUTH_TTL_SECS);
        self.pending_codes
            .retain(|_, v| now - v.created_at < AUTH_CODE_TTL_SECS);
        self.bearer_sessions
            .retain(|_, v| now < v.bearer_expires_at);
    }

    /// Check if adding to the given map would exceed limits. Returns true if full.
    pub fn is_bearer_sessions_full(&self) -> bool {
        self.bearer_sessions.len() >= MAX_BEARER_SESSIONS
    }

    pub fn is_pending_codes_full(&self) -> bool {
        self.pending_codes.len() >= MAX_PENDING_CODES
    }

    pub fn is_pending_auths_full(&self) -> bool {
        self.pending_auths.len() >= MAX_PENDING_AUTHS
    }

    pub fn is_registered_clients_full(&self) -> bool {
        self.registered_clients.len() >= MAX_REGISTERED_CLIENTS
    }
}

/// Generate a cryptographically secure random token (256-bit).
pub fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64_url_encode(&buf)
}

/// Validate that a redirect URI has a safe scheme.
pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let lower = uri.to_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err(format!(
        "Unsafe redirect_uri scheme: {uri}. Only https:// or http://localhost are allowed."
    ))
}

/// Validate that a gateway base URL uses HTTPS (except for localhost).
pub fn validate_gateway_base_url(url: &str) -> Result<(), String> {
    let lower = url.to_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if lower.starts_with("http://localhost")
        || lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://[::1]")
    {
        return Ok(());
    }
    Err(format!(
        "gateway-base-url must use https:// (got: {url}). http:// is only allowed for localhost."
    ))
}

/// Exchange a Google authorization code for tokens.
pub async fn exchange_google_code(
    config: &OAuthConfig,
    code: &str,
) -> anyhow::Result<GoogleTokens> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            (
                "redirect_uri",
                &format!("{}/oauth/callback", config.base_url),
            ),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        // Phase 3-5: Limit error log length.
        let truncated = if body.len() > 500 { &body[..500] } else { &body };
        anyhow::bail!("Google token exchange failed: {truncated}");
    }

    let body: serde_json::Value = resp.json().await?;
    parse_google_token_response(&body)
}

/// Refresh a Google access token using a refresh token.
pub async fn refresh_google_token(
    config: &OAuthConfig,
    refresh_token: &str,
) -> anyhow::Result<GoogleTokens> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("refresh_token", refresh_token),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        let truncated = if body.len() > 500 { &body[..500] } else { &body };
        anyhow::bail!("Google token refresh failed: {truncated}");
    }

    let body: serde_json::Value = resp.json().await?;
    let mut tokens = parse_google_token_response(&body)?;
    // Google doesn't return refresh_token on refresh — keep the original.
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_token.to_string());
    }
    Ok(tokens)
}

fn parse_google_token_response(body: &serde_json::Value) -> anyhow::Result<GoogleTokens> {
    let access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing access_token in Google token response"))?
        .to_string();
    let refresh_token = body["refresh_token"].as_str().map(|s| s.to_string());
    let expires_in = body["expires_in"].as_i64();
    let expires_at = expires_in.map(|ei| chrono::Utc::now().timestamp() + ei);

    Ok(GoogleTokens {
        access_token,
        refresh_token,
        expires_at,
    })
}

/// Fetch the authenticated user's email from the Google userinfo endpoint.
pub async fn get_google_userinfo(access_token: &str) -> anyhow::Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        let truncated = if body.len() > 500 { &body[..500] } else { &body };
        anyhow::bail!("Google userinfo request failed: {truncated}");
    }

    let body: serde_json::Value = resp.json().await?;
    body["email"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Missing email in userinfo response"))
}

/// Validate a PKCE `code_verifier` against the stored `code_challenge`.
/// Only S256 is supported; plain is rejected.
pub fn validate_pkce(
    code_verifier: &str,
    code_challenge: &str,
    method: Option<&str>,
) -> bool {
    match method.unwrap_or("S256") {
        "S256" => {
            let digest = sha2::Sha256::digest(code_verifier.as_bytes());
            let computed = base64_url_encode(&digest);
            computed == code_challenge
        }
        _ => false,
    }
}

pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Get a valid Google access token for a bearer session, refreshing if needed.
pub async fn get_valid_google_token(
    config: &OAuthConfig,
    store: &Mutex<TokenStore>,
    bearer_token: &str,
) -> anyhow::Result<String> {
    // Check bearer token expiry and current Google token state.
    let (needs_refresh, refresh_token_opt) = {
        let guard = store.lock().await;
        let session = guard
            .bearer_sessions
            .get(bearer_token)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        // Check bearer token expiry.
        if chrono::Utc::now().timestamp() >= session.bearer_expires_at {
            anyhow::bail!("Bearer token expired");
        }

        if session.google_tokens.is_expired() {
            (true, session.google_tokens.refresh_token.clone())
        } else {
            return Ok(session.google_tokens.access_token.clone());
        }
    };

    if needs_refresh {
        let rt = refresh_token_opt
            .ok_or_else(|| anyhow::anyhow!("Cannot refresh: no refresh_token available"))?;
        let new_tokens = refresh_google_token(config, &rt).await?;
        let access_token = new_tokens.access_token.clone();

        let mut guard = store.lock().await;
        if let Some(session) = guard.bearer_sessions.get_mut(bearer_token) {
            session.google_tokens = new_tokens;
        }
        return Ok(access_token);
    }

    unreachable!()
}

/// Look up the user email associated with a bearer token.
///
/// Returns `None` when the bearer token is not found in the store
/// (e.g. OAuth is disabled or the session has expired).
pub async fn get_email_for_bearer(
    store: &Mutex<TokenStore>,
    bearer_token: &str,
) -> Option<String> {
    let guard = store.lock().await;
    guard
        .bearer_sessions
        .get(bearer_token)
        .map(|s| s.email.clone())
}

/// Build the Google OAuth authorization URL for the consent screen.
pub fn build_google_auth_url(config: &OAuthConfig, state: &str) -> String {
    let redirect_uri =
        percent_encoding::utf8_percent_encode(
            &format!("{}/oauth/callback", config.base_url),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
    let scope = percent_encoding::utf8_percent_encode(
        &config.scopes,
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();

    format!(
        "https://accounts.google.com/o/oauth2/auth\
         ?client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &response_type=code\
         &scope={scope}\
         &state={state}\
         &access_type=offline\
         &prompt=consent",
        client_id = config.client_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pkce_s256() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = base64_url_encode(&digest);

        assert!(validate_pkce(verifier, &challenge, Some("S256")));
        assert!(validate_pkce(verifier, &challenge, None)); // default is S256
    }

    #[test]
    fn test_validate_pkce_s256_wrong_verifier() {
        let verifier = "correct-verifier";
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = base64_url_encode(&digest);

        assert!(!validate_pkce("wrong-verifier", &challenge, Some("S256")));
    }

    #[test]
    fn test_validate_pkce_plain_rejected() {
        // plain method is no longer accepted — only S256
        assert!(!validate_pkce("my-code", "my-code", Some("plain")));
    }

    #[test]
    fn test_validate_pkce_unknown_method() {
        assert!(!validate_pkce("v", "c", Some("unknown")));
    }

    #[test]
    fn test_google_tokens_not_expired() {
        let tokens = GoogleTokens {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
        };
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_google_tokens_expired() {
        let tokens = GoogleTokens {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() - 10),
        };
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_google_tokens_expires_within_buffer() {
        let tokens = GoogleTokens {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() + 30),
        };
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_google_tokens_no_expiry() {
        let tokens = GoogleTokens {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: None,
        };
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_token_store_bearer_sessions() {
        let mut store = TokenStore::new();
        assert!(store.bearer_sessions.get("tok").is_none());

        store.bearer_sessions.insert(
            "tok".to_string(),
            UserSession {
                email: "user@example.com".to_string(),
                google_tokens: GoogleTokens {
                    access_token: "gat".to_string(),
                    refresh_token: None,
                    expires_at: None,
                },
                bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
            },
        );

        let session = store.bearer_sessions.get("tok").unwrap();
        assert_eq!(session.email, "user@example.com");
        assert_eq!(session.google_tokens.access_token, "gat");
    }

    #[tokio::test]
    async fn test_get_email_for_bearer_found() {
        let store = tokio::sync::Mutex::new(TokenStore::new());
        {
            let mut guard = store.lock().await;
            guard.bearer_sessions.insert(
                "bearer-abc".to_string(),
                UserSession {
                    email: "alice@example.com".to_string(),
                    google_tokens: GoogleTokens {
                        access_token: "gat".to_string(),
                        refresh_token: None,
                        expires_at: None,
                    },
                    bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
                },
            );
        }
        let email = get_email_for_bearer(&store, "bearer-abc").await;
        assert_eq!(email.as_deref(), Some("alice@example.com"));
    }

    #[tokio::test]
    async fn test_get_email_for_bearer_not_found() {
        let store = tokio::sync::Mutex::new(TokenStore::new());
        let email = get_email_for_bearer(&store, "nonexistent").await;
        assert!(email.is_none());
    }

    #[test]
    fn test_token_store_pending_auth_lifecycle() {
        let mut store = TokenStore::new();
        store.pending_auths.insert(
            "state1".to_string(),
            PendingAuth {
                client_redirect_uri: "https://example.com/callback".to_string(),
                client_state: Some("cs".to_string()),
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                client_id: "client1".to_string(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );

        assert!(store.pending_auths.contains_key("state1"));
        let auth = store.pending_auths.remove("state1").unwrap();
        assert_eq!(auth.client_state, Some("cs".to_string()));
        assert!(store.pending_auths.get("state1").is_none());
    }

    #[test]
    fn test_token_store_pending_code_lifecycle() {
        let mut store = TokenStore::new();
        store.pending_codes.insert(
            "code1".to_string(),
            PendingCode {
                session: UserSession {
                    email: "u@e.com".to_string(),
                    google_tokens: GoogleTokens {
                        access_token: "at".to_string(),
                        refresh_token: Some("rt".to_string()),
                        expires_at: None,
                    },
                    bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
                },
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                created_at: chrono::Utc::now().timestamp(),
            },
        );

        let code = store.pending_codes.remove("code1").unwrap();
        assert_eq!(code.session.email, "u@e.com");
        assert!(store.pending_codes.get("code1").is_none());
    }

    #[test]
    fn test_parse_google_token_response_full() {
        let body = serde_json::json!({
            "access_token": "ya29.xxx",
            "refresh_token": "1//xxx",
            "expires_in": 3600,
            "token_type": "Bearer"
        });
        let tokens = parse_google_token_response(&body).unwrap();
        assert_eq!(tokens.access_token, "ya29.xxx");
        assert_eq!(tokens.refresh_token.as_deref(), Some("1//xxx"));
        assert!(tokens.expires_at.is_some());
    }

    #[test]
    fn test_parse_google_token_response_no_refresh() {
        let body = serde_json::json!({
            "access_token": "ya29.xxx",
            "expires_in": 3600
        });
        let tokens = parse_google_token_response(&body).unwrap();
        assert_eq!(tokens.access_token, "ya29.xxx");
        assert!(tokens.refresh_token.is_none());
    }

    #[test]
    fn test_parse_google_token_response_missing_access_token() {
        let body = serde_json::json!({ "error": "invalid_grant" });
        let err = parse_google_token_response(&body).unwrap_err();
        assert!(err.to_string().contains("Missing access_token"));
    }

    #[test]
    fn test_build_google_auth_url() {
        let config = OAuthConfig {
            client_id: "test-client-id".to_string(),
            client_secret: "secret".to_string(),
            base_url: "https://gw.example.com".to_string(),
            scopes: "openid email".to_string(),
        };
        let url = build_google_auth_url(&config, "state123");
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/auth"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello";
        let encoded = base64_url_encode(data);
        assert_eq!(encoded, "aGVsbG8");
    }

    #[test]
    fn test_generate_secure_token_length() {
        let token = generate_secure_token();
        // 32 bytes base64url encoded = 43 characters
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_secure_token_unique() {
        let t1 = generate_secure_token();
        let t2 = generate_secure_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_validate_redirect_uri_https() {
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
    }

    #[test]
    fn test_validate_redirect_uri_localhost() {
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("http://127.0.0.1:8080/cb").is_ok());
        assert!(validate_redirect_uri("http://[::1]:3000/cb").is_ok());
    }

    #[test]
    fn test_validate_redirect_uri_rejects_http() {
        assert!(validate_redirect_uri("http://example.com/callback").is_err());
    }

    #[test]
    fn test_validate_redirect_uri_rejects_dangerous() {
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("data:text/html,<h1>hi</h1>").is_err());
        assert!(validate_redirect_uri("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_gateway_base_url_https() {
        assert!(validate_gateway_base_url("https://gw.example.com").is_ok());
    }

    #[test]
    fn test_validate_gateway_base_url_localhost() {
        assert!(validate_gateway_base_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn test_validate_gateway_base_url_rejects_http() {
        assert!(validate_gateway_base_url("http://remote.example.com").is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let mut store = TokenStore::new();
        let past = chrono::Utc::now().timestamp() - 10000;

        store.pending_auths.insert(
            "old".to_string(),
            PendingAuth {
                client_redirect_uri: "https://x.com/cb".to_string(),
                client_state: None,
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                client_id: "c".to_string(),
                created_at: past,
            },
        );
        store.pending_codes.insert(
            "old_code".to_string(),
            PendingCode {
                session: UserSession {
                    email: "u@e.com".to_string(),
                    google_tokens: GoogleTokens {
                        access_token: "at".to_string(),
                        refresh_token: None,
                        expires_at: None,
                    },
                    bearer_expires_at: past,
                },
                code_challenge: "cc".to_string(),
                code_challenge_method: "S256".to_string(),
                created_at: past,
            },
        );
        store.bearer_sessions.insert(
            "old_bearer".to_string(),
            UserSession {
                email: "u@e.com".to_string(),
                google_tokens: GoogleTokens {
                    access_token: "at".to_string(),
                    refresh_token: None,
                    expires_at: None,
                },
                bearer_expires_at: past,
            },
        );

        store.cleanup_expired();

        assert!(store.pending_auths.is_empty());
        assert!(store.pending_codes.is_empty());
        assert!(store.bearer_sessions.is_empty());
    }

    #[test]
    fn test_oauth_config_debug_redacts_secret() {
        let config = OAuthConfig {
            client_id: "id".to_string(),
            client_secret: "super-secret-value".to_string(),
            base_url: "https://gw.example.com".to_string(),
            scopes: "openid".to_string(),
        };
        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("super-secret-value"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}
