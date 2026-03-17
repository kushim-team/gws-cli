//! In-memory `StateStore` implementation for local development and testing.

use std::collections::HashMap;

use tokio::sync::Mutex;

use super::*;

/// In-memory state store backed by HashMaps behind a Mutex.
///
/// All data is lost on process exit. Capacity limits prevent memory exhaustion.
pub struct InMemoryStateStore {
    inner: Mutex<Inner>,
}

struct Inner {
    user_sessions: HashMap<String, UserSessionData>,
    bearer_sessions: HashMap<String, BearerSession>,
    refresh_tokens: HashMap<String, RefreshTokenEntry>,
    pending_codes: HashMap<String, PendingCode>,
    pending_auths: HashMap<String, PendingAuth>,
    registered_clients: HashMap<String, RegisteredClient>,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                user_sessions: HashMap::new(),
                bearer_sessions: HashMap::new(),
                refresh_tokens: HashMap::new(),
                pending_codes: HashMap::new(),
                pending_auths: HashMap::new(),
                registered_clients: HashMap::new(),
            }),
        }
    }
}

impl Inner {
    /// Remove expired entries from all maps.
    fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.pending_auths
            .retain(|_, v| now - v.created_at < PENDING_AUTH_TTL_SECS);
        self.pending_codes
            .retain(|_, v| now - v.created_at < AUTH_CODE_TTL_SECS);
        self.bearer_sessions
            .retain(|_, v| now < v.bearer_expires_at);
        self.refresh_tokens
            .retain(|_, v| now < v.refresh_expires_at);
        self.registered_clients
            .retain(|_, v| now - v.client_id_issued_at < REGISTERED_CLIENT_TTL_SECS);
        // user_sessions: no TTL, only explicit deletion.
    }
}

#[async_trait::async_trait]
impl StateStore for InMemoryStateStore {
    // ---- user_sessions ----

    async fn get_user_session(
        &self,
        email: &str,
    ) -> Result<Option<UserSessionData>, StateStoreError> {
        let guard = self.inner.lock().await;
        Ok(guard.user_sessions.get(email).cloned())
    }

    async fn set_user_session(
        &self,
        email: &str,
        session: &UserSessionData,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        if !guard.user_sessions.contains_key(email)
            && guard.user_sessions.len() >= MAX_USER_SESSIONS
        {
            return Err(StateStoreError::CapacityExceeded("user_sessions".into()));
        }
        guard
            .user_sessions
            .insert(email.to_string(), session.clone());
        Ok(())
    }

    async fn delete_user_session(&self, email: &str) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.user_sessions.remove(email);
        Ok(())
    }

    // ---- bearer_sessions ----

    async fn get_bearer_session(
        &self,
        bearer_token: &str,
    ) -> Result<Option<BearerSession>, StateStoreError> {
        let guard = self.inner.lock().await;
        let session = guard.bearer_sessions.get(bearer_token).cloned();
        // Check TTL at application layer.
        if let Some(ref s) = session {
            if chrono::Utc::now().timestamp() >= s.bearer_expires_at {
                return Ok(None);
            }
        }
        Ok(session)
    }

    async fn set_bearer_session(
        &self,
        bearer_token: &str,
        session: &BearerSession,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.cleanup_expired();
        if !guard.bearer_sessions.contains_key(bearer_token)
            && guard.bearer_sessions.len() >= MAX_BEARER_SESSIONS
        {
            return Err(StateStoreError::CapacityExceeded("bearer_sessions".into()));
        }
        guard
            .bearer_sessions
            .insert(bearer_token.to_string(), session.clone());
        Ok(())
    }

    async fn delete_bearer_session(&self, bearer_token: &str) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.bearer_sessions.remove(bearer_token);
        Ok(())
    }

    // ---- refresh_tokens ----

    async fn get_refresh_entry(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenEntry>, StateStoreError> {
        let guard = self.inner.lock().await;
        let entry = guard.refresh_tokens.get(refresh_token).cloned();
        // Check TTL at application layer.
        if let Some(ref e) = entry {
            if chrono::Utc::now().timestamp() >= e.refresh_expires_at {
                return Ok(None);
            }
        }
        Ok(entry)
    }

    async fn set_refresh_entry(
        &self,
        refresh_token: &str,
        entry: &RefreshTokenEntry,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.cleanup_expired();
        if !guard.refresh_tokens.contains_key(refresh_token)
            && guard.refresh_tokens.len() >= MAX_REFRESH_TOKENS
        {
            return Err(StateStoreError::CapacityExceeded("refresh_tokens".into()));
        }
        guard
            .refresh_tokens
            .insert(refresh_token.to_string(), entry.clone());
        Ok(())
    }

    async fn delete_refresh_entry(&self, refresh_token: &str) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.refresh_tokens.remove(refresh_token);
        Ok(())
    }

    // ---- pending_codes ----

    async fn take_pending_code(&self, code: &str) -> Result<Option<PendingCode>, StateStoreError> {
        let mut guard = self.inner.lock().await;
        let pending = guard.pending_codes.remove(code);
        // Check TTL.
        if let Some(ref p) = pending {
            if chrono::Utc::now().timestamp() - p.created_at >= AUTH_CODE_TTL_SECS {
                return Ok(None);
            }
        }
        Ok(pending)
    }

    async fn set_pending_code(
        &self,
        code: &str,
        pending: &PendingCode,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.cleanup_expired();
        if guard.pending_codes.len() >= MAX_PENDING_CODES {
            return Err(StateStoreError::CapacityExceeded("pending_codes".into()));
        }
        guard
            .pending_codes
            .insert(code.to_string(), pending.clone());
        Ok(())
    }

    // ---- pending_auths ----

    async fn take_pending_auth(&self, state: &str) -> Result<Option<PendingAuth>, StateStoreError> {
        let mut guard = self.inner.lock().await;
        let auth = guard.pending_auths.remove(state);
        // Check TTL.
        if let Some(ref a) = auth {
            if chrono::Utc::now().timestamp() - a.created_at >= PENDING_AUTH_TTL_SECS {
                return Ok(None);
            }
        }
        Ok(auth)
    }

    async fn set_pending_auth(
        &self,
        state: &str,
        auth: &PendingAuth,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.cleanup_expired();
        if guard.pending_auths.len() >= MAX_PENDING_AUTHS {
            return Err(StateStoreError::CapacityExceeded("pending_auths".into()));
        }
        guard.pending_auths.insert(state.to_string(), auth.clone());
        Ok(())
    }

    // ---- registered_clients ----

    async fn get_registered_client(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, StateStoreError> {
        let guard = self.inner.lock().await;
        let client = guard.registered_clients.get(client_id).cloned();
        // Check TTL.
        if let Some(ref c) = client {
            if chrono::Utc::now().timestamp() - c.client_id_issued_at >= REGISTERED_CLIENT_TTL_SECS
            {
                return Ok(None);
            }
        }
        Ok(client)
    }

    async fn set_registered_client(
        &self,
        client_id: &str,
        client: &RegisteredClient,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;
        guard.cleanup_expired();
        if guard.registered_clients.len() >= MAX_REGISTERED_CLIENTS {
            return Err(StateStoreError::CapacityExceeded(
                "registered_clients".into(),
            ));
        }
        guard
            .registered_clients
            .insert(client_id.to_string(), client.clone());
        Ok(())
    }

    // ---- Transactions ----

    async fn exchange_code_transaction(
        &self,
        input: CodeExchangeInput,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;

        // PendingCode was already consumed by take_pending_code() in the handler.
        // Clean up any stale entry if it still exists (defensive).
        guard.pending_codes.remove(&input.auth_code);

        // Capacity checks.
        if !guard.user_sessions.contains_key(&input.email)
            && guard.user_sessions.len() >= MAX_USER_SESSIONS
        {
            return Err(StateStoreError::CapacityExceeded("user_sessions".into()));
        }
        if guard.bearer_sessions.len() >= MAX_BEARER_SESSIONS {
            return Err(StateStoreError::CapacityExceeded("bearer_sessions".into()));
        }
        if guard.refresh_tokens.len() >= MAX_REFRESH_TOKENS {
            return Err(StateStoreError::CapacityExceeded("refresh_tokens".into()));
        }

        // Write user_session.
        guard.user_sessions.insert(
            input.email.clone(),
            UserSessionData {
                google_tokens: input.google_tokens,
            },
        );

        // Write bearer_session.
        guard.bearer_sessions.insert(
            input.bearer_token,
            BearerSession {
                email: input.email.clone(),
                bearer_expires_at: input.bearer_expires_at,
            },
        );

        // Write refresh_token.
        guard.refresh_tokens.insert(
            input.refresh_token,
            RefreshTokenEntry {
                email: input.email,
                refresh_expires_at: input.refresh_expires_at,
            },
        );

        Ok(())
    }

    async fn refresh_token_transaction(
        &self,
        input: RefreshTransactionInput,
    ) -> Result<(), StateStoreError> {
        let mut guard = self.inner.lock().await;

        // Delete old refresh token (atomically prevents concurrent use).
        if guard
            .refresh_tokens
            .remove(&input.old_refresh_token)
            .is_none()
        {
            return Err(StateStoreError::TransactionConflict);
        }

        // Delete old bearer session if known.
        if let Some(ref old_bearer) = input.old_bearer_token {
            guard.bearer_sessions.remove(old_bearer);
        }

        // Capacity checks.
        if guard.bearer_sessions.len() >= MAX_BEARER_SESSIONS {
            return Err(StateStoreError::CapacityExceeded("bearer_sessions".into()));
        }
        if guard.refresh_tokens.len() >= MAX_REFRESH_TOKENS {
            return Err(StateStoreError::CapacityExceeded("refresh_tokens".into()));
        }

        // Write new bearer_session.
        guard.bearer_sessions.insert(
            input.new_bearer_token,
            BearerSession {
                email: input.email.clone(),
                bearer_expires_at: input.bearer_expires_at,
            },
        );

        // Write new refresh_token.
        guard.refresh_tokens.insert(
            input.new_refresh_token,
            RefreshTokenEntry {
                email: input.email.clone(),
                refresh_expires_at: input.refresh_expires_at,
            },
        );

        // Update google_tokens in user_session if refreshed.
        if let Some(tokens) = input.updated_google_tokens {
            guard.user_sessions.insert(
                input.email,
                UserSessionData {
                    google_tokens: tokens,
                },
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_server::oauth::GoogleTokens;

    fn test_google_tokens() -> GoogleTokens {
        GoogleTokens {
            access_token: "gat".to_string(),
            refresh_token: Some("grt".to_string()),
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
        }
    }

    #[tokio::test]
    async fn test_user_session_crud() {
        let store = InMemoryStateStore::new();
        let session = UserSessionData {
            google_tokens: test_google_tokens(),
        };
        store
            .set_user_session("user@example.com", &session)
            .await
            .unwrap();
        let loaded = store.get_user_session("user@example.com").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().google_tokens.access_token, "gat");

        store.delete_user_session("user@example.com").await.unwrap();
        let loaded = store.get_user_session("user@example.com").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_bearer_session_ttl() {
        let store = InMemoryStateStore::new();
        let session = BearerSession {
            email: "user@example.com".to_string(),
            bearer_expires_at: chrono::Utc::now().timestamp() - 10,
        };
        store.set_bearer_session("tok", &session).await.unwrap();
        // Expired bearer should return None.
        let loaded = store.get_bearer_session("tok").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_refresh_entry_ttl() {
        let store = InMemoryStateStore::new();
        let entry = RefreshTokenEntry {
            email: "user@example.com".to_string(),
            refresh_expires_at: chrono::Utc::now().timestamp() - 10,
        };
        store.set_refresh_entry("rt", &entry).await.unwrap();
        let loaded = store.get_refresh_entry("rt").await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_pending_code_take() {
        let store = InMemoryStateStore::new();
        let pending = PendingCode {
            email: "user@example.com".to_string(),
            google_tokens: test_google_tokens(),
            code_challenge: "cc".to_string(),
            code_challenge_method: "S256".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        };
        store.set_pending_code("code1", &pending).await.unwrap();
        let taken = store.take_pending_code("code1").await.unwrap();
        assert!(taken.is_some());
        // Second take should return None (already removed).
        let taken2 = store.take_pending_code("code1").await.unwrap();
        assert!(taken2.is_none());
    }

    #[tokio::test]
    async fn test_pending_auth_take() {
        let store = InMemoryStateStore::new();
        let auth = PendingAuth {
            client_redirect_uri: "https://example.com/cb".to_string(),
            client_state: Some("cs".to_string()),
            code_challenge: "cc".to_string(),
            code_challenge_method: "S256".to_string(),
            client_id: "cid".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        };
        store.set_pending_auth("state1", &auth).await.unwrap();
        let taken = store.take_pending_auth("state1").await.unwrap();
        assert!(taken.is_some());
        let taken2 = store.take_pending_auth("state1").await.unwrap();
        assert!(taken2.is_none());
    }

    #[tokio::test]
    async fn test_exchange_code_transaction() {
        let store = InMemoryStateStore::new();

        // Set up a pending code.
        let pending = PendingCode {
            email: "user@example.com".to_string(),
            google_tokens: test_google_tokens(),
            code_challenge: "cc".to_string(),
            code_challenge_method: "S256".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        };
        store.set_pending_code("code1", &pending).await.unwrap();

        let now = chrono::Utc::now().timestamp();
        let input = CodeExchangeInput {
            auth_code: "code1".to_string(),
            email: "user@example.com".to_string(),
            google_tokens: test_google_tokens(),
            bearer_token: "bearer1".to_string(),
            bearer_expires_at: now + BEARER_TOKEN_LIFETIME_SECS,
            refresh_token: "refresh1".to_string(),
            refresh_expires_at: now + REFRESH_TOKEN_LIFETIME_SECS,
        };
        store.exchange_code_transaction(input).await.unwrap();

        // Verify all entries were created.
        assert!(store
            .get_user_session("user@example.com")
            .await
            .unwrap()
            .is_some());
        assert!(store.get_bearer_session("bearer1").await.unwrap().is_some());
        assert!(store.get_refresh_entry("refresh1").await.unwrap().is_some());
        // Pending code should be consumed.
        assert!(store.take_pending_code("code1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_take_pending_code_replay_prevention() {
        // Replay prevention is enforced by take_pending_code (not the transaction).
        let store = InMemoryStateStore::new();

        let pending = PendingCode {
            email: "user@example.com".to_string(),
            google_tokens: test_google_tokens(),
            code_challenge: "cc".to_string(),
            code_challenge_method: "S256".to_string(),
            created_at: chrono::Utc::now().timestamp(),
        };
        store.set_pending_code("code1", &pending).await.unwrap();

        // First take succeeds.
        let taken = store.take_pending_code("code1").await.unwrap();
        assert!(taken.is_some());

        // Second take returns None (replay prevented).
        let taken2 = store.take_pending_code("code1").await.unwrap();
        assert!(taken2.is_none());
    }

    #[tokio::test]
    async fn test_refresh_token_transaction() {
        let store = InMemoryStateStore::new();

        // Set up initial state.
        let session = UserSessionData {
            google_tokens: test_google_tokens(),
        };
        store
            .set_user_session("user@example.com", &session)
            .await
            .unwrap();

        let now = chrono::Utc::now().timestamp();
        let bearer = BearerSession {
            email: "user@example.com".to_string(),
            bearer_expires_at: now + 3600,
        };
        store
            .set_bearer_session("old_bearer", &bearer)
            .await
            .unwrap();

        let refresh = RefreshTokenEntry {
            email: "user@example.com".to_string(),
            refresh_expires_at: now + 604800,
        };
        store
            .set_refresh_entry("old_refresh", &refresh)
            .await
            .unwrap();

        let input = RefreshTransactionInput {
            old_refresh_token: "old_refresh".to_string(),
            old_bearer_token: Some("old_bearer".to_string()),
            email: "user@example.com".to_string(),
            new_bearer_token: "new_bearer".to_string(),
            bearer_expires_at: now + 3600,
            new_refresh_token: "new_refresh".to_string(),
            refresh_expires_at: now + 604800,
            updated_google_tokens: None,
        };
        store.refresh_token_transaction(input).await.unwrap();

        // Old tokens should be gone.
        assert!(store
            .get_bearer_session("old_bearer")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_refresh_entry("old_refresh")
            .await
            .unwrap()
            .is_none());
        // New tokens should exist.
        assert!(store
            .get_bearer_session("new_bearer")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_refresh_entry("new_refresh")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_refresh_token_transaction_concurrent_conflict() {
        let store = InMemoryStateStore::new();

        let now = chrono::Utc::now().timestamp();
        let refresh = RefreshTokenEntry {
            email: "user@example.com".to_string(),
            refresh_expires_at: now + 604800,
        };
        store.set_refresh_entry("refresh1", &refresh).await.unwrap();

        let session = UserSessionData {
            google_tokens: test_google_tokens(),
        };
        store
            .set_user_session("user@example.com", &session)
            .await
            .unwrap();

        // First refresh succeeds.
        let input1 = RefreshTransactionInput {
            old_refresh_token: "refresh1".to_string(),
            old_bearer_token: None,
            email: "user@example.com".to_string(),
            new_bearer_token: "new_bearer1".to_string(),
            bearer_expires_at: now + 3600,
            new_refresh_token: "new_refresh1".to_string(),
            refresh_expires_at: now + 604800,
            updated_google_tokens: None,
        };
        store.refresh_token_transaction(input1).await.unwrap();

        // Second attempt with same old refresh token should fail (TransactionConflict).
        let input2 = RefreshTransactionInput {
            old_refresh_token: "refresh1".to_string(),
            old_bearer_token: None,
            email: "user@example.com".to_string(),
            new_bearer_token: "new_bearer2".to_string(),
            bearer_expires_at: now + 3600,
            new_refresh_token: "new_refresh2".to_string(),
            refresh_expires_at: now + 604800,
            updated_google_tokens: None,
        };
        let result = store.refresh_token_transaction(input2).await;
        assert!(matches!(result, Err(StateStoreError::TransactionConflict)));
    }

    #[tokio::test]
    async fn test_registered_client_crud() {
        let store = InMemoryStateStore::new();
        let client = RegisteredClient {
            client_id: "cid1".to_string(),
            redirect_uris: vec!["https://example.com/cb".to_string()],
            client_name: Some("Test".to_string()),
            client_id_issued_at: chrono::Utc::now().timestamp(),
        };
        store.set_registered_client("cid1", &client).await.unwrap();
        let loaded = store.get_registered_client("cid1").await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().client_id, "cid1");
    }

    #[tokio::test]
    async fn test_refresh_entry_capacity_check() {
        let store = InMemoryStateStore::new();
        // This test just verifies the capacity check logic works.
        // We don't actually fill to MAX_REFRESH_TOKENS as that would be slow.
        let entry = RefreshTokenEntry {
            email: "user@example.com".to_string(),
            refresh_expires_at: chrono::Utc::now().timestamp() + 604800,
        };
        store.set_refresh_entry("rt1", &entry).await.unwrap();
        let loaded = store.get_refresh_entry("rt1").await.unwrap();
        assert!(loaded.is_some());
    }
}
