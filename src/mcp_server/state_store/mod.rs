//! Stateless state management for the MCP Gateway.
//!
//! Provides a `StateStore` trait abstracting all server-side state, with two
//! implementations:
//! - `InMemoryStateStore`: HashMap-based, for local development and testing.
//! - `FirestoreStateStore`: Firestore REST API, for production (Cloud Run).
//!
//! The server is fully stateless — all state lives in the store. This enables
//! multi-instance deployments and survives restarts.

mod firestore;
mod in_memory;

pub use firestore::FirestoreStateStore;
pub use in_memory::InMemoryStateStore;

use super::oauth::GoogleTokens;

/// Maximum number of entries in each collection (InMemory only).
const MAX_USER_SESSIONS: usize = 10_000;
const MAX_BEARER_SESSIONS: usize = 100_000;
const MAX_REFRESH_TOKENS: usize = 100_000;
const MAX_PENDING_CODES: usize = 10_000;
const MAX_PENDING_AUTHS: usize = 10_000;
const MAX_REGISTERED_CLIENTS: usize = 10_000;

/// Bearer token lifetime in seconds (1 hour).
pub const BEARER_TOKEN_LIFETIME_SECS: i64 = 3600;

/// Refresh token lifetime in seconds (7 days).
pub const REFRESH_TOKEN_LIFETIME_SECS: i64 = 604_800;

/// Authorization code TTL in seconds (10 minutes).
pub const AUTH_CODE_TTL_SECS: i64 = 600;

/// Pending auth TTL in seconds (15 minutes).
pub const PENDING_AUTH_TTL_SECS: i64 = 900;

/// Registered client TTL in seconds (7 days).
pub const REGISTERED_CLIENT_TTL_SECS: i64 = 604_800;

// ---- Data structures ----

/// User's Google OAuth session, keyed by email in `user_sessions`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSessionData {
    pub google_tokens: GoogleTokens,
}

/// Bearer token session, keyed by bearer_token in `bearer_sessions`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BearerSession {
    pub email: String,
    pub bearer_expires_at: i64,
}

/// Refresh token entry, keyed by refresh_token in `refresh_tokens`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RefreshTokenEntry {
    pub email: String,
    pub refresh_expires_at: i64,
    /// The bearer token associated with this refresh token,
    /// used to invalidate the old bearer on refresh.
    #[serde(default)]
    pub bearer_token: Option<String>,
}

/// State tracked between `/authorize` redirect and `/oauth/callback`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingAuth {
    pub client_redirect_uri: String,
    pub client_state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[allow(dead_code)]
    pub client_id: String,
    pub created_at: i64,
}

/// State tracked between `/oauth/callback` and `POST /token` exchange.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingCode {
    pub email: String,
    pub google_tokens: GoogleTokens,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub created_at: i64,
}

/// A dynamically registered OAuth client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub client_id_issued_at: i64,
}

/// Input for the authorization code exchange transaction.
pub struct CodeExchangeInput {
    pub auth_code: String,
    pub email: String,
    pub google_tokens: GoogleTokens,
    pub bearer_token: String,
    pub bearer_expires_at: i64,
    pub refresh_token: String,
    pub refresh_expires_at: i64,
}

/// Input for the refresh token transaction.
pub struct RefreshTransactionInput {
    pub old_refresh_token: String,
    pub old_bearer_token: Option<String>,
    pub email: String,
    pub new_bearer_token: String,
    pub bearer_expires_at: i64,
    pub new_refresh_token: String,
    pub refresh_expires_at: i64,
    pub updated_google_tokens: Option<GoogleTokens>,
}

/// Errors from state store operations.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum StateStoreError {
    #[error("capacity exceeded: {0}")]
    CapacityExceeded(String),
    #[error("not found")]
    NotFound,
    #[error("transaction conflict")]
    TransactionConflict,
    #[error("store unavailable: {0}")]
    Unavailable(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Trait abstracting all server-side state for the MCP Gateway.
///
/// All methods are async to support both in-memory and remote backends.
/// The trait is object-safe for use as `Arc<dyn StateStore>`.
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    // ---- user_sessions ----

    async fn get_user_session(
        &self,
        email: &str,
    ) -> Result<Option<UserSessionData>, StateStoreError>;
    async fn set_user_session(
        &self,
        email: &str,
        session: &UserSessionData,
    ) -> Result<(), StateStoreError>;
    async fn delete_user_session(&self, email: &str) -> Result<(), StateStoreError>;

    // ---- bearer_sessions ----

    async fn get_bearer_session(
        &self,
        bearer_token: &str,
    ) -> Result<Option<BearerSession>, StateStoreError>;
    async fn set_bearer_session(
        &self,
        bearer_token: &str,
        session: &BearerSession,
    ) -> Result<(), StateStoreError>;
    async fn delete_bearer_session(&self, bearer_token: &str) -> Result<(), StateStoreError>;

    // ---- refresh_tokens ----

    async fn get_refresh_entry(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshTokenEntry>, StateStoreError>;
    async fn set_refresh_entry(
        &self,
        refresh_token: &str,
        entry: &RefreshTokenEntry,
    ) -> Result<(), StateStoreError>;
    async fn delete_refresh_entry(&self, refresh_token: &str) -> Result<(), StateStoreError>;

    // ---- pending_codes ----

    async fn take_pending_code(&self, code: &str) -> Result<Option<PendingCode>, StateStoreError>;
    async fn set_pending_code(
        &self,
        code: &str,
        pending: &PendingCode,
    ) -> Result<(), StateStoreError>;

    // ---- pending_auths ----

    async fn take_pending_auth(&self, state: &str) -> Result<Option<PendingAuth>, StateStoreError>;
    async fn set_pending_auth(
        &self,
        state: &str,
        auth: &PendingAuth,
    ) -> Result<(), StateStoreError>;

    // ---- registered_clients ----

    async fn get_registered_client(
        &self,
        client_id: &str,
    ) -> Result<Option<RegisteredClient>, StateStoreError>;
    async fn set_registered_client(
        &self,
        client_id: &str,
        client: &RegisteredClient,
    ) -> Result<(), StateStoreError>;

    // ---- Transactions ----

    /// Atomically exchange an authorization code for tokens.
    ///
    /// Deletes the PendingCode, then creates user_session, bearer_session,
    /// and refresh_token entries. On InMemory this is a single Mutex lock;
    /// on Firestore this is a Firestore transaction.
    async fn exchange_code_transaction(
        &self,
        input: CodeExchangeInput,
    ) -> Result<(), StateStoreError>;

    /// Atomically rotate bearer + refresh tokens.
    ///
    /// Deletes the old refresh_token and bearer_session, creates new ones,
    /// and optionally updates the user_session's google_tokens.
    async fn refresh_token_transaction(
        &self,
        input: RefreshTransactionInput,
    ) -> Result<(), StateStoreError>;
}
