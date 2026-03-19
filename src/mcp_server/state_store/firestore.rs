//! Firestore-backed `StateStore` for production (Cloud Run).
//!
//! Uses the Firestore REST API directly (no gRPC dependency).
//! All documents are encrypted at the application layer with AES-256-GCM
//! before being written to Firestore.

use super::*;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use sha2::Digest;

/// Hash a token value using SHA-256 for use as a Firestore document ID.
/// This prevents raw token values from appearing in Firestore REST URLs
/// and GCP audit logs.
fn hash_token(token: &str) -> String {
    let digest = sha2::Sha256::digest(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

const BASE_URL: &str = "https://firestore.googleapis.com/v1";

/// Firestore-backed state store with AES-256-GCM encryption.
///
/// Each document has two fields:
/// - `data`: JSON serialized → AES-256-GCM encrypted → Base64 encoded string.
/// - `expires_at`: Firestore TTL timestamp (None for `user_sessions`).
pub struct FirestoreStateStore {
    project: String,
    database: String,
    http_client: reqwest::Client,
    cipher: Aes256Gcm,
}

impl FirestoreStateStore {
    /// Create a new Firestore state store.
    ///
    /// `encryption_key` must be exactly 32 bytes (256 bits).
    pub fn new(project: String, database: String, encryption_key: &[u8; 32]) -> Self {
        let cipher =
            Aes256Gcm::new_from_slice(encryption_key).expect("AES-256-GCM key must be 32 bytes");
        Self {
            project,
            database,
            http_client: reqwest::Client::new(),
            cipher,
        }
    }

    /// Create a new Firestore state store, loading the encryption key from Secret Manager.
    ///
    /// `encryption_key_secret` is the Secret Manager secret name (e.g. "mcp-gateway-encryption-key").
    /// The secret value must be exactly 32 bytes (raw) or 44 characters (Base64-encoded 32 bytes).
    pub async fn from_secret_manager(
        project: String,
        database: String,
        encryption_key_secret: String,
    ) -> Result<Self, anyhow::Error> {
        let http_client = reqwest::Client::new();

        // Get access token from metadata server.
        let token_resp = http_client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?;
        let token_body: serde_json::Value = token_resp.json().await?;
        let access_token = token_body["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing access_token from metadata server"))?;

        // Fetch secret from Secret Manager.
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
            project, encryption_key_secret
        );
        let resp = http_client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Secret Manager fetch failed: {body}");
        }
        let body: serde_json::Value = resp.json().await?;
        let payload_b64 = body["payload"]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing payload.data in Secret Manager response"))?;
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "encryption key must be exactly 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let key: [u8; 32] = key_bytes.try_into().unwrap();

        Ok(Self::new(project, database, &key))
    }

    /// Get an access token from the GCP metadata server (Cloud Run / GCE).
    async fn get_access_token(&self) -> Result<String, StateStoreError> {
        let resp = self
            .http_client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("metadata server: {e}")))?;

        if !resp.status().is_success() {
            return Err(StateStoreError::Unavailable(format!(
                "metadata token: {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("metadata parse: {e}")))?;
        body["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| StateStoreError::Unavailable("missing access_token in metadata".into()))
    }

    fn base_path(&self) -> String {
        format!(
            "{}/projects/{}/databases/{}/documents",
            BASE_URL, self.project, self.database
        )
    }

    /// Encrypt data using AES-256-GCM and return Base64-encoded result.
    ///
    /// Format: Base64(nonce || ciphertext || tag)
    fn encrypt(&self, plaintext: &[u8]) -> Result<String, StateStoreError> {
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StateStoreError::Other(anyhow::anyhow!("encryption failed: {e}")))?;

        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
    }

    /// Decrypt Base64-encoded AES-256-GCM data.
    fn decrypt(&self, encoded: &str) -> Result<Vec<u8>, StateStoreError> {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| StateStoreError::Other(anyhow::anyhow!("base64 decode failed: {e}")))?;

        if combined.len() < 12 {
            return Err(StateStoreError::Other(anyhow::anyhow!(
                "encrypted data too short"
            )));
        }

        let nonce = Nonce::from_slice(&combined[..12]);
        let ciphertext = &combined[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StateStoreError::Other(anyhow::anyhow!("decryption failed: {e}")))
    }

    /// Serialize, encrypt, and build Firestore document fields.
    fn build_document<T: serde::Serialize>(
        &self,
        data: &T,
        expires_at: Option<i64>,
    ) -> Result<serde_json::Value, StateStoreError> {
        let json_bytes = serde_json::to_vec(data)
            .map_err(|e| StateStoreError::Other(anyhow::anyhow!("serialization failed: {e}")))?;
        let encrypted = self.encrypt(&json_bytes)?;

        let mut fields = serde_json::json!({
            "data": { "stringValue": encrypted }
        });

        if let Some(ts) = expires_at {
            let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(chrono::Utc::now);
            fields["expires_at"] = serde_json::json!({
                "timestampValue": dt.to_rfc3339()
            });
        }

        Ok(serde_json::json!({ "fields": fields }))
    }

    /// Parse and decrypt a Firestore document into a typed struct.
    fn parse_document<T: serde::de::DeserializeOwned>(
        &self,
        doc: &serde_json::Value,
    ) -> Result<T, StateStoreError> {
        let data_str = doc["fields"]["data"]["stringValue"]
            .as_str()
            .ok_or_else(|| StateStoreError::Other(anyhow::anyhow!("missing data field")))?;

        let plaintext = self.decrypt(data_str)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| StateStoreError::Other(anyhow::anyhow!("deserialization failed: {e}")))
    }

    /// GET a single document. Returns None if not found.
    async fn get_doc<T: serde::de::DeserializeOwned>(
        &self,
        collection: &str,
        doc_id: &str,
    ) -> Result<Option<T>, StateStoreError> {
        let token = self.get_access_token().await?;
        let url = format!("{}/{}/{}", self.base_path(), collection, doc_id);

        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("firestore get: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > 300 {
                &body[..300]
            } else {
                &body
            };
            return Err(StateStoreError::Unavailable(format!(
                "firestore get {collection}/{doc_id}: {status} {truncated}"
            )));
        }

        let doc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("firestore parse: {e}")))?;

        match self.parse_document(&doc) {
            Ok(val) => Ok(Some(val)),
            Err(_) => {
                // Decryption failure (e.g., key rotation) — treat as not found.
                tracing::warn!(
                    collection = collection,
                    doc_id = doc_id,
                    "decryption failed, treating as not found"
                );
                Ok(None)
            }
        }
    }

    /// Create or overwrite a document.
    async fn set_doc<T: serde::Serialize>(
        &self,
        collection: &str,
        doc_id: &str,
        data: &T,
        expires_at: Option<i64>,
    ) -> Result<(), StateStoreError> {
        let token = self.get_access_token().await?;
        let url = format!("{}/{}?documentId={}", self.base_path(), collection, doc_id);
        let document = self.build_document(data, expires_at)?;

        // Use PATCH (upsert) with the document name.
        let patch_url = format!("{}/{}/{}", self.base_path(), collection, doc_id);
        let resp = self
            .http_client
            .patch(&patch_url)
            .bearer_auth(&token)
            .json(&document)
            .send()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("firestore set: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > 300 {
                &body[..300]
            } else {
                &body
            };
            return Err(StateStoreError::Unavailable(format!(
                "firestore set {collection}/{doc_id}: {status} {truncated}"
            )));
        }

        let _ = url; // suppress unused warning
        Ok(())
    }

    /// Delete a document. Ignores NOT_FOUND.
    async fn delete_doc(&self, collection: &str, doc_id: &str) -> Result<(), StateStoreError> {
        let token = self.get_access_token().await?;
        let url = format!("{}/{}/{}", self.base_path(), collection, doc_id);

        let resp = self
            .http_client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("firestore delete: {e}")))?;

        if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NOT_FOUND {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let truncated = if body.len() > 300 {
                &body[..300]
            } else {
                &body
            };
            return Err(StateStoreError::Unavailable(format!(
                "firestore delete {collection}/{doc_id}: {status} {truncated}"
            )));
        }
        Ok(())
    }

    /// Execute a Firestore commit (transaction) with a list of writes.
    async fn commit_transaction(
        &self,
        writes: Vec<serde_json::Value>,
    ) -> Result<(), StateStoreError> {
        let token = self.get_access_token().await?;
        let url = format!(
            "{}/projects/{}/databases/{}/documents:commit",
            BASE_URL, self.project, self.database
        );

        let body = serde_json::json!({ "writes": writes });

        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| StateStoreError::Unavailable(format!("firestore commit: {e}")))?;

        if resp.status() == reqwest::StatusCode::CONFLICT {
            return Err(StateStoreError::TransactionConflict);
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Firestore returns FAILED_PRECONDITION (HTTP 400) when a
            // currentDocument precondition is not met (e.g. document already
            // deleted). Treat this the same as CONFLICT for take-once semantics.
            if body.contains("FAILED_PRECONDITION") {
                return Err(StateStoreError::TransactionConflict);
            }

            let truncated = if body.len() > 300 {
                &body[..300]
            } else {
                &body
            };
            return Err(StateStoreError::Unavailable(format!(
                "firestore commit: {status} {truncated}"
            )));
        }

        Ok(())
    }

    /// Build a Firestore document path.
    fn doc_path(&self, collection: &str, doc_id: &str) -> String {
        format!(
            "projects/{}/databases/{}/documents/{}/{}",
            self.project, self.database, collection, doc_id
        )
    }

    /// Build a Firestore write operation (update/upsert).
    fn build_write<T: serde::Serialize>(
        &self,
        collection: &str,
        doc_id: &str,
        data: &T,
        expires_at: Option<i64>,
    ) -> Result<serde_json::Value, StateStoreError> {
        let mut doc = self.build_document(data, expires_at)?;
        doc["name"] = serde_json::json!(self.doc_path(collection, doc_id));
        Ok(serde_json::json!({
            "update": doc
        }))
    }

    /// Build a Firestore delete operation.
    fn build_delete_write(&self, collection: &str, doc_id: &str) -> serde_json::Value {
        serde_json::json!({
            "delete": self.doc_path(collection, doc_id)
        })
    }

    /// Build a Firestore delete operation with `currentDocument.exists: true` precondition.
    /// This ensures the delete fails (CONFLICT) if the document was already deleted by
    /// a concurrent request, providing atomicity for take-once semantics.
    fn build_preconditioned_delete_write(
        &self,
        collection: &str,
        doc_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "delete": self.doc_path(collection, doc_id),
            "currentDocument": { "exists": true }
        })
    }
}

#[async_trait::async_trait]
impl StateStore for FirestoreStateStore {
    // ---- user_sessions (no TTL) ----

    async fn get_user_session(
        &self,
        email: &str,
    ) -> Result<Option<UserSessionData>, StateStoreError> {
        let hashed = hash_token(email);
        self.get_doc("user_sessions", &hashed).await
    }

    async fn set_user_session(
        &self,
        email: &str,
        session: &UserSessionData,
    ) -> Result<(), StateStoreError> {
        let hashed = hash_token(email);
        self.set_doc("user_sessions", &hashed, session, None).await
    }

    async fn delete_user_session(&self, email: &str) -> Result<(), StateStoreError> {
        let hashed = hash_token(email);
        self.delete_doc("user_sessions", &hashed).await
    }

    // ---- bearer_sessions ----

    async fn get_bearer_session(
        &self,
        bearer_token: &str,
    ) -> Result<Option<BearerSession>, StateStoreError> {
        let hashed = hash_token(bearer_token);
        let session: Option<BearerSession> = self.get_doc("bearer_sessions", &hashed).await?;
        // Application-layer TTL check.
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
        let hashed = hash_token(bearer_token);
        self.set_doc(
            "bearer_sessions",
            &hashed,
            session,
            Some(session.bearer_expires_at),
        )
        .await
    }

    async fn delete_bearer_session(&self, bearer_token: &str) -> Result<(), StateStoreError> {
        let hashed = hash_token(bearer_token);
        self.delete_doc("bearer_sessions", &hashed).await
    }

    async fn delete_bearer_session_by_stored_key(&self, key: &str) -> Result<(), StateStoreError> {
        // Firestore stores hashed bearer tokens as document IDs,
        // and RefreshTokenEntry.bearer_token already contains the hash.
        self.delete_doc("bearer_sessions", key).await
    }

    // ---- refresh_tokens ----

    async fn get_refresh_entry(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenEntry>, StateStoreError> {
        let hashed = hash_token(refresh_token);
        let entry: Option<RefreshTokenEntry> = self.get_doc("refresh_tokens", &hashed).await?;
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
        let hashed = hash_token(refresh_token);
        self.set_doc(
            "refresh_tokens",
            &hashed,
            entry,
            Some(entry.refresh_expires_at),
        )
        .await
    }

    async fn delete_refresh_entry(&self, refresh_token: &str) -> Result<(), StateStoreError> {
        let hashed = hash_token(refresh_token);
        self.delete_doc("refresh_tokens", &hashed).await
    }

    // ---- pending_codes ----

    async fn take_pending_code(&self, code: &str) -> Result<Option<PendingCode>, StateStoreError> {
        let hashed = hash_token(code);
        let pending: Option<PendingCode> = self.get_doc("pending_codes", &hashed).await?;
        if pending.is_some() {
            // Use preconditioned delete via commit to prevent concurrent take.
            let writes = vec![self.build_preconditioned_delete_write("pending_codes", &hashed)];
            self.commit_transaction(writes).await?;
        }
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
        let hashed = hash_token(code);
        let expires_at = pending.created_at + AUTH_CODE_TTL_SECS;
        self.set_doc("pending_codes", &hashed, pending, Some(expires_at))
            .await
    }

    // ---- pending_auths ----

    async fn take_pending_auth(&self, state: &str) -> Result<Option<PendingAuth>, StateStoreError> {
        let hashed = hash_token(state);
        let auth: Option<PendingAuth> = self.get_doc("pending_auths", &hashed).await?;
        if auth.is_some() {
            // Use preconditioned delete via commit to prevent concurrent take.
            let writes = vec![self.build_preconditioned_delete_write("pending_auths", &hashed)];
            self.commit_transaction(writes).await?;
        }
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
        let hashed = hash_token(state);
        let expires_at = auth.created_at + PENDING_AUTH_TTL_SECS;
        self.set_doc("pending_auths", &hashed, auth, Some(expires_at))
            .await
    }

    // ---- registered_clients ----

    async fn get_registered_client(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, StateStoreError> {
        let client: Option<RegisteredClient> =
            self.get_doc("registered_clients", client_id).await?;
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
        let expires_at = client.client_id_issued_at + REGISTERED_CLIENT_TTL_SECS;
        self.set_doc("registered_clients", client_id, client, Some(expires_at))
            .await
    }

    // ---- Transactions ----

    async fn exchange_code_transaction(
        &self,
        input: CodeExchangeInput,
    ) -> Result<(), StateStoreError> {
        let now = chrono::Utc::now().timestamp();
        let _ = now; // used in expires_at calculations below

        let mut writes = Vec::new();

        // Delete PendingCode (preconditioned: must exist to prevent replay).
        let hashed_code = hash_token(&input.auth_code);
        writes.push(self.build_preconditioned_delete_write("pending_codes", &hashed_code));

        // Upsert user_session.
        let user_session = UserSessionData {
            google_tokens: input.google_tokens,
        };
        let hashed_email = hash_token(&input.email);
        writes.push(self.build_write("user_sessions", &hashed_email, &user_session, None)?);

        // Create bearer_session.
        let bearer = BearerSession {
            email: input.email.clone(),
            bearer_expires_at: input.bearer_expires_at,
        };
        let hashed_bearer = hash_token(&input.bearer_token);
        writes.push(self.build_write(
            "bearer_sessions",
            &hashed_bearer,
            &bearer,
            Some(input.bearer_expires_at),
        )?);

        // Create refresh_token — store hashed bearer token to avoid
        // exposing raw bearer on encryption key compromise.
        let refresh = RefreshTokenEntry {
            email: input.email,
            refresh_expires_at: input.refresh_expires_at,
            bearer_token: Some(hashed_bearer.clone()),
        };
        let hashed_refresh = hash_token(&input.refresh_token);
        writes.push(self.build_write(
            "refresh_tokens",
            &hashed_refresh,
            &refresh,
            Some(input.refresh_expires_at),
        )?);

        self.commit_transaction(writes).await
    }

    async fn refresh_token_transaction(
        &self,
        input: RefreshTransactionInput,
    ) -> Result<(), StateStoreError> {
        let mut writes = Vec::new();

        // Delete old refresh token (preconditioned: must exist to prevent concurrent rotation).
        let hashed_old_refresh = hash_token(&input.old_refresh_token);
        writes.push(self.build_preconditioned_delete_write("refresh_tokens", &hashed_old_refresh));

        // Delete old bearer session if known.
        // old_bearer_token is already a hashed key (stored by this impl).
        if let Some(ref old_bearer_key) = input.old_bearer_token {
            writes.push(self.build_delete_write("bearer_sessions", old_bearer_key));
        }

        // Create new bearer_session.
        let bearer = BearerSession {
            email: input.email.clone(),
            bearer_expires_at: input.bearer_expires_at,
        };
        let hashed_new_bearer = hash_token(&input.new_bearer_token);
        writes.push(self.build_write(
            "bearer_sessions",
            &hashed_new_bearer,
            &bearer,
            Some(input.bearer_expires_at),
        )?);

        // Create new refresh_token — store hashed bearer token.
        let refresh = RefreshTokenEntry {
            email: input.email.clone(),
            refresh_expires_at: input.refresh_expires_at,
            bearer_token: Some(hashed_new_bearer.clone()),
        };
        let hashed_new_refresh = hash_token(&input.new_refresh_token);
        writes.push(self.build_write(
            "refresh_tokens",
            &hashed_new_refresh,
            &refresh,
            Some(input.refresh_expires_at),
        )?);

        // Update user_session google_tokens if refreshed.
        if let Some(tokens) = input.updated_google_tokens {
            let session = UserSessionData {
                google_tokens: tokens,
            };
            let hashed_email = hash_token(&input.email);
            writes.push(self.build_write("user_sessions", &hashed_email, &session, None)?);
        }

        self.commit_transaction(writes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let store =
            FirestoreStateStore::new("test-project".to_string(), "test-db".to_string(), &key);

        let plaintext = b"hello world, this is a secret!";
        let encrypted = store.encrypt(plaintext).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let key = [0x42u8; 32];
        let store =
            FirestoreStateStore::new("test-project".to_string(), "test-db".to_string(), &key);

        let plaintext = b"same data";
        let enc1 = store.encrypt(plaintext).unwrap();
        let enc2 = store.encrypt(plaintext).unwrap();
        // Different nonces should produce different ciphertexts.
        assert_ne!(enc1, enc2);
        // But both should decrypt to the same plaintext.
        assert_eq!(store.decrypt(&enc1).unwrap(), store.decrypt(&enc2).unwrap());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let store1 = FirestoreStateStore::new("p".to_string(), "d".to_string(), &key1);
        let store2 = FirestoreStateStore::new("p".to_string(), "d".to_string(), &key2);

        let encrypted = store1.encrypt(b"secret").unwrap();
        assert!(store2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_build_document_with_expires_at() {
        let key = [0x42u8; 32];
        let store = FirestoreStateStore::new("p".to_string(), "d".to_string(), &key);

        let data = BearerSession {
            email: "user@example.com".to_string(),
            bearer_expires_at: 1700000000,
        };
        let doc = store.build_document(&data, Some(1700000000)).unwrap();
        assert!(doc["fields"]["data"]["stringValue"].is_string());
        assert!(doc["fields"]["expires_at"]["timestampValue"].is_string());
    }

    #[test]
    fn test_build_document_without_expires_at() {
        let key = [0x42u8; 32];
        let store = FirestoreStateStore::new("p".to_string(), "d".to_string(), &key);

        let data = UserSessionData {
            google_tokens: crate::mcp_server::oauth::GoogleTokens {
                access_token: "at".to_string(),
                refresh_token: None,
                expires_at: None,
            },
        };
        let doc = store.build_document(&data, None).unwrap();
        assert!(doc["fields"]["data"]["stringValue"].is_string());
        assert!(doc["fields"]["expires_at"].is_null());
    }
}
