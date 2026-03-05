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

/// OAuth configuration for the MCP Gateway.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
    pub scopes: String,
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
}

/// State tracked between the `/authorize` redirect and the `/oauth/callback`.
#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub client_redirect_uri: String,
    pub client_state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// State tracked between the `/oauth/callback` and the `POST /token` exchange.
#[derive(Debug, Clone)]
pub struct PendingCode {
    pub session: UserSession,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// A dynamically registered OAuth client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
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
        anyhow::bail!("Google token exchange failed: {body}");
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
        anyhow::bail!("Google token refresh failed: {body}");
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
        anyhow::bail!("Google userinfo request failed: {body}");
    }

    let body: serde_json::Value = resp.json().await?;
    body["email"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Missing email in userinfo response"))
}

/// Validate a PKCE `code_verifier` against the stored `code_challenge`.
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
        "plain" => code_verifier == code_challenge,
        _ => false,
    }
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Get a valid Google access token for a bearer session, refreshing if needed.
pub async fn get_valid_google_token(
    config: &OAuthConfig,
    store: &Mutex<TokenStore>,
    bearer_token: &str,
) -> anyhow::Result<String> {
    // Check current token state.
    let (needs_refresh, refresh_token_opt) = {
        let guard = store.lock().await;
        let session = guard
            .bearer_sessions
            .get(bearer_token)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

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
        // code_verifier → SHA256 → base64url = code_challenge
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
    fn test_validate_pkce_plain() {
        assert!(validate_pkce("my-code", "my-code", Some("plain")));
        assert!(!validate_pkce("my-code", "other-code", Some("plain")));
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
        // Token expires in 30 seconds — within the 60-second buffer
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
            },
        );

        let session = store.bearer_sessions.get("tok").unwrap();
        assert_eq!(session.email, "user@example.com");
        assert_eq!(session.google_tokens.access_token, "gat");
    }

    #[test]
    fn test_token_store_pending_auth_lifecycle() {
        let mut store = TokenStore::new();
        store.pending_auths.insert(
            "state1".to_string(),
            PendingAuth {
                client_redirect_uri: "https://example.com/callback".to_string(),
                client_state: Some("cs".to_string()),
                code_challenge: Some("cc".to_string()),
                code_challenge_method: Some("S256".to_string()),
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
                },
                code_challenge: Some("cc".to_string()),
                code_challenge_method: Some("S256".to_string()),
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
        // Known test vector
        let data = b"hello";
        let encoded = base64_url_encode(data);
        assert_eq!(encoded, "aGVsbG8"); // base64url("hello") without padding
    }
}
