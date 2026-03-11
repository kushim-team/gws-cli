//! Session persistence backends for the MCP Gateway.
//!
//! Provides a trait for persisting bearer sessions (which contain Google OAuth
//! refresh tokens) and two implementations:
//! - `InMemoryPersistence`: no-op, sessions live only in memory (local dev).
//! - `SecretManagerPersistence`: stores sessions in GCP Secret Manager (Cloud Run).

use std::collections::HashMap;

use super::oauth::UserSession;

/// Trait for persisting bearer sessions across process restarts.
///
/// Only `bearer_sessions` are persisted — ephemeral state like pending auth
/// codes and registered clients remain in-memory only.
#[async_trait::async_trait]
pub trait SessionPersistence: Send + Sync {
    /// Load all persisted sessions. Returns an empty map on first run.
    async fn load(&self) -> anyhow::Result<HashMap<String, UserSession>>;

    /// Persist the full sessions map (overwrite).
    async fn save(&self, sessions: &HashMap<String, UserSession>) -> anyhow::Result<()>;
}

/// No-op persistence for local development. Sessions are in-memory only.
pub struct InMemoryPersistence;

#[async_trait::async_trait]
impl SessionPersistence for InMemoryPersistence {
    async fn load(&self) -> anyhow::Result<HashMap<String, UserSession>> {
        Ok(HashMap::new())
    }

    async fn save(&self, _sessions: &HashMap<String, UserSession>) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Persists sessions to GCP Secret Manager as a JSON blob.
///
/// Uses the metadata server for authentication (works on Cloud Run).
/// All sessions are stored in a single secret as one JSON object.
pub struct SecretManagerPersistence {
    project: String,
    secret_id: String,
    http_client: reqwest::Client,
}

impl SecretManagerPersistence {
    pub fn new(project: String, secret_id: String) -> Self {
        Self {
            project,
            secret_id,
            http_client: reqwest::Client::new(),
        }
    }

    /// Get an access token from the GCP metadata server (Cloud Run / GCE).
    async fn get_access_token(&self) -> anyhow::Result<String> {
        let resp = self
            .http_client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("Failed to get metadata token: {}", resp.status());
        }

        let body: serde_json::Value = resp.json().await?;
        body["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Missing access_token in metadata response"))
    }

    /// Ensure the secret exists, creating it if necessary.
    async fn ensure_secret_exists(&self, token: &str) -> anyhow::Result<()> {
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}",
            self.project, self.secret_id
        );
        let resp = self.http_client.get(&url).bearer_auth(token).send().await?;

        if resp.status().is_success() {
            return Ok(());
        }

        // Create the secret if it doesn't exist (404).
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            let create_url = format!(
                "https://secretmanager.googleapis.com/v1/projects/{}/secrets",
                self.project
            );
            let resp = self
                .http_client
                .post(&create_url)
                .bearer_auth(token)
                .query(&[("secretId", &self.secret_id)])
                .json(&serde_json::json!({
                    "replication": { "automatic": {} }
                }))
                .send()
                .await?;

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                let truncated = if body.len() > 500 {
                    &body[..500]
                } else {
                    &body
                };
                anyhow::bail!("Failed to create secret: {truncated}");
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl SessionPersistence for SecretManagerPersistence {
    async fn load(&self) -> anyhow::Result<HashMap<String, UserSession>> {
        let token = self.get_access_token().await?;
        self.ensure_secret_exists(&token).await?;

        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
            self.project, self.secret_id
        );
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        // No versions yet — return empty.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(HashMap::new());
        }

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > 500 {
                &body[..500]
            } else {
                &body
            };
            anyhow::bail!("Failed to access secret version: {truncated}");
        }

        let body: serde_json::Value = resp.json().await?;
        let data_b64 = body["payload"]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing payload.data in secret response"))?;

        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD.decode(data_b64)?;
        let sessions: HashMap<String, UserSession> = serde_json::from_slice(&bytes)?;
        Ok(sessions)
    }

    async fn save(&self, sessions: &HashMap<String, UserSession>) -> anyhow::Result<()> {
        let token = self.get_access_token().await?;

        let json_bytes = serde_json::to_vec(sessions)?;
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&json_bytes);

        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}:addVersion",
            self.project, self.secret_id
        );
        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "payload": { "data": encoded }
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > 500 {
                &body[..500]
            } else {
                &body
            };
            anyhow::bail!("Failed to add secret version: {truncated}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_server::oauth::GoogleTokens;

    #[tokio::test]
    async fn test_in_memory_persistence_load_returns_empty() {
        let p = InMemoryPersistence;
        let sessions = p.load().await.unwrap();
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn test_in_memory_persistence_save_is_noop() {
        let p = InMemoryPersistence;
        let mut sessions = HashMap::new();
        sessions.insert(
            "tok".to_string(),
            UserSession {
                email: "test@example.com".to_string(),
                google_tokens: GoogleTokens {
                    access_token: "at".to_string(),
                    refresh_token: Some("rt".to_string()),
                    expires_at: Some(9999999999),
                },
                bearer_expires_at: 9999999999,
            },
        );
        // save succeeds but does nothing
        p.save(&sessions).await.unwrap();
        // load still returns empty
        let loaded = p.load().await.unwrap();
        assert!(loaded.is_empty());
    }
}
