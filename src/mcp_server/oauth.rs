//! OAuth token management for the MCP Gateway.
//!
//! Handles Google OAuth flow delegation, PKCE validation,
//! and automatic token refresh.

use sha2::Digest;
use std::sync::Arc;

use super::state_store::{StateStore, StateStoreError, UserSessionData};

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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GoogleTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when the access token expires.
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for GoogleTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleTokens")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl GoogleTokens {
    /// Returns true if the token is expired or will expire within 60 seconds.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|ea| chrono::Utc::now().timestamp() + 60 >= ea)
            .unwrap_or(false)
    }
}

/// Generate a cryptographically secure random token (256-bit).
pub fn generate_secure_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64_url_encode(&buf)
}

/// Check if a URL's host portion is a localhost variant.
/// Returns true if the host is exactly "localhost", "127.0.0.1", or "[::1]".
fn is_localhost_url(lower: &str) -> bool {
    for prefix in &["http://localhost", "http://127.0.0.1", "http://[::1]"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            if rest.is_empty()
                || rest.starts_with(':')
                || rest.starts_with('/')
                || rest.starts_with('?')
                || rest.starts_with('#')
            {
                return true;
            }
        }
    }
    false
}

/// Validate that a redirect URI has a safe scheme.
pub fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let lower = uri.to_lowercase();
    if lower.starts_with("https://") {
        return Ok(());
    }
    if is_localhost_url(&lower) {
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
    if is_localhost_url(&lower) {
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
        let truncated = if body.len() > 500 {
            &body[..500]
        } else {
            &body
        };
        anyhow::bail!("Google token exchange failed: {truncated}");
    }

    let body: serde_json::Value = resp.json().await?;
    parse_google_token_response(&body)
}

/// Refresh a Google access token using a refresh token.
///
/// Returns `Err` with a message containing "invalid_grant" if Google rejects
/// the refresh token (revoked, password changed, etc.).
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
        let truncated = if body.len() > 500 {
            &body[..500]
        } else {
            &body
        };
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
        let truncated = if body.len() > 500 {
            &body[..500]
        } else {
            &body
        };
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
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate_pkce(code_verifier: &str, code_challenge: &str, method: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;
    match method.unwrap_or("S256") {
        "S256" => {
            let digest = sha2::Sha256::digest(code_verifier.as_bytes());
            let computed = base64_url_encode(&digest);
            computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
        }
        _ => false,
    }
}

pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Get a valid Google access token for a bearer session, refreshing if needed.
///
/// On Google `invalid_grant`, deletes the user_session and bearer_session
/// from the store and returns an error.
pub async fn get_valid_google_token(
    config: &OAuthConfig,
    store: &Arc<dyn StateStore>,
    bearer_token: &str,
) -> anyhow::Result<String> {
    // Look up bearer session.
    let bearer_session = store
        .get_bearer_session(bearer_token)
        .await
        .map_err(|e| match e {
            StateStoreError::Unavailable(msg) => anyhow::anyhow!("Store unavailable: {msg}"),
            other => anyhow::anyhow!("{other}"),
        })?
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

    // Check bearer token expiry.
    if chrono::Utc::now().timestamp() >= bearer_session.bearer_expires_at {
        anyhow::bail!("Bearer token expired");
    }

    let email = &bearer_session.email;

    // Look up user session to get Google tokens.
    let user_session = store
        .get_user_session(email)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("User session not found"))?;

    if !user_session.google_tokens.is_expired() {
        return Ok(user_session.google_tokens.access_token.clone());
    }

    // Google token expired — refresh it.
    let rt = user_session
        .google_tokens
        .refresh_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Cannot refresh: no refresh_token available"))?;

    match refresh_google_token(config, rt).await {
        Ok(new_tokens) => {
            let access_token = new_tokens.access_token.clone();
            // Update user_session with new Google tokens.
            let updated = UserSessionData {
                google_tokens: new_tokens,
            };
            if let Err(e) = store.set_user_session(email, &updated).await {
                tracing::warn!(error = %e, "failed to update user_session after Google token refresh");
            }
            Ok(access_token)
        }
        Err(e) => {
            // H-5: On Google invalid_grant, invalidate the session.
            if e.to_string().contains("invalid_grant") {
                tracing::warn!(
                    email = email,
                    "Google refresh token invalid, invalidating session"
                );
                let _ = store.delete_user_session(email).await;
                let _ = store.delete_bearer_session(bearer_token).await;
            }
            Err(e)
        }
    }
}

/// Look up the user email associated with a bearer token.
///
/// Returns `None` when the bearer token is not found in the store
/// (e.g. OAuth is disabled or the session has expired).
pub async fn get_email_for_bearer(
    store: &Arc<dyn StateStore>,
    bearer_token: &str,
) -> Option<String> {
    match store.get_bearer_session(bearer_token).await {
        Ok(Some(session)) => Some(session.email),
        _ => None,
    }
}

/// Build the Google OAuth authorization URL for the consent screen.
pub fn build_google_auth_url(config: &OAuthConfig, state: &str) -> String {
    let redirect_uri = percent_encoding::utf8_percent_encode(
        &format!("{}/oauth/callback", config.base_url),
        percent_encoding::NON_ALPHANUMERIC,
    )
    .to_string();
    let scope =
        percent_encoding::utf8_percent_encode(&config.scopes, percent_encoding::NON_ALPHANUMERIC)
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
    use crate::mcp_server::state_store::InMemoryStateStore;

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

    #[tokio::test]
    async fn test_get_email_for_bearer_found() {
        let store: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::new());
        let session = crate::mcp_server::state_store::BearerSession {
            email: "alice@example.com".to_string(),
            bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
        };
        store
            .set_bearer_session("bearer-abc", &session)
            .await
            .unwrap();
        let email = get_email_for_bearer(&store, "bearer-abc").await;
        assert_eq!(email.as_deref(), Some("alice@example.com"));
    }

    #[tokio::test]
    async fn test_get_email_for_bearer_not_found() {
        let store: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::new());
        let email = get_email_for_bearer(&store, "nonexistent").await;
        assert!(email.is_none());
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
