use super::jsonrpc::{build_jsonrpc_response, build_parse_error_response};
use super::oauth::{self, OAuthConfig};
use super::permissions::{PermissionContext, PermissionsConfig};
use super::state_store::{self, StateStore, StateStoreError};
use super::*;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
struct AppState {
    config: ServerConfig,
    tools_cache: Mutex<Option<Vec<Value>>>,
    allowed_origins: Vec<String>,
    oauth_config: OAuthConfig,
    state_store: Arc<dyn StateStore>,
    permissions: Option<PermissionsConfig>,
}

pub(super) async fn serve(
    config: ServerConfig,
    host: &str,
    port: u16,
    allow_origin: &str,
    oauth_config: OAuthConfig,
    permissions: Option<PermissionsConfig>,
    store: Arc<dyn StateStore>,
) -> Result<(), GwsError> {
    let allowed_origins: Vec<String> = if allow_origin.is_empty() {
        vec![]
    } else {
        allow_origin
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    };

    let state = Arc::new(AppState {
        config,
        tools_cache: Mutex::new(None),
        allowed_origins,
        oauth_config,
        state_store: store,
        permissions,
    });

    let app = Router::new()
        .route("/mcp", post(handle_post))
        .route("/mcp", get(handle_get))
        .route("/mcp", delete(handle_delete))
        .route(
            "/.well-known/oauth-authorization-server",
            get(handle_oauth_metadata),
        )
        .route("/authorize", get(handle_authorize))
        .route("/oauth/callback", get(handle_oauth_callback))
        .route("/token", post(handle_token).options(handle_cors_preflight))
        .route(
            "/register",
            post(handle_register).options(handle_cors_preflight),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state);

    let addr: std::net::SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| GwsError::Other(anyhow::anyhow!("Invalid host address: {e}")))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| GwsError::Other(anyhow::anyhow!("Failed to bind to {addr}: {e}")))?;

    tracing::info!(addr = %addr, "HTTP server listening");

    axum::serve(listener, app)
        .await
        .map_err(|e| GwsError::Other(anyhow::anyhow!("HTTP server error: {e}")))?;

    Ok(())
}

// ---- helpers ----

async fn security_headers_middleware(
    request: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    response
}

fn get_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn validate_origin(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) => o,
        None => return true,
    };
    if !allowed_origins.is_empty() {
        return allowed_origins.iter().any(|a| a == origin);
    }
    let lower = origin.to_lowercase();
    is_localhost_origin(&lower)
}

/// Check if an origin is a localhost variant (http or https).
/// Ensures the host is exactly "localhost", "127.0.0.1", or "[::1]"
/// (not e.g. "localhost.evil.com").
fn is_localhost_origin(lower: &str) -> bool {
    for prefix in &[
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://[::1]",
        "https://[::1]",
    ] {
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

/// Extract bearer token from Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

/// Resolve the Google access token for the current request.
/// Requires a valid bearer token and refreshes if needed.
/// Returns `Err(Response)` with 401 if auth is missing/invalid.
fn www_authenticate_header(state: &AppState) -> String {
    let base_url = &state.oauth_config.base_url;
    format!(
        "Bearer realm=\"mcp\", resource_metadata=\"{base_url}/.well-known/oauth-authorization-server\""
    )
}

fn unauthorized_response(state: &AppState, msg: &str) -> Response {
    let www_auth = www_authenticate_header(state);
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", www_auth.as_str())],
        msg.to_string(),
    )
        .into_response()
}

async fn resolve_google_token(headers: &HeaderMap, state: &AppState) -> Result<String, Response> {
    let bearer = extract_bearer_token(headers)
        .ok_or_else(|| unauthorized_response(state, "Authentication required"))?;

    match oauth::get_valid_google_token(&state.oauth_config, &state.state_store, &bearer).await {
        Ok(token) => Ok(token),
        Err(e) => {
            tracing::warn!("Bearer auth failed: {e}");
            Err(unauthorized_response(state, "Invalid or expired token"))
        }
    }
}

// ---- MCP endpoints ----

async fn handle_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !validate_origin(&headers, &state.allowed_origins) {
        return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
    }

    if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
        let has_json = accept.contains("application/json") || accept.contains("*/*");
        let has_sse = accept.contains("text/event-stream") || accept.contains("*/*");
        if !has_json || !has_sse {
            return (
                StatusCode::NOT_ACCEPTABLE,
                "Accept header must include both application/json and text/event-stream",
            )
                .into_response();
        }
    }

    // Resolve Google token (returns 401 if no valid bearer)
    let google_token = match resolve_google_token(&headers, &state).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            let error_resp = build_parse_error_response();
            return (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                serde_json::to_string(&error_resp).unwrap(),
            )
                .into_response();
        }
    };

    let (messages, is_batch) = if let Some(arr) = parsed.as_array() {
        (arr.clone(), true)
    } else {
        (vec![parsed], false)
    };

    if messages.is_empty() {
        let error_resp = json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32600, "message": "Invalid Request: empty batch" }
        });
        return (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            serde_json::to_string(&error_resp).unwrap(),
        )
            .into_response();
    }

    let bearer_for_binding = extract_bearer_token(&headers).unwrap_or_default();
    let mut new_session_id: Option<String> = None;

    // Resolve user email from bearer token for permission checks and logging.
    let user_email = if !bearer_for_binding.is_empty() {
        oauth::get_email_for_bearer(&state.state_store, &bearer_for_binding).await
    } else {
        None
    };
    let perm_ctx = PermissionContext {
        user_email: user_email.as_deref(),
        permissions: state.permissions.as_ref(),
    };

    let mut responses = Vec::new();

    for msg in &messages {
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
        let has_id = msg.get("id").is_some();
        let has_method = msg.get("method").is_some();

        if !has_id || !has_method {
            if has_method {
                let _ = handle_request(
                    method,
                    &params,
                    &state.config,
                    &state.tools_cache,
                    &google_token,
                    &perm_ctx,
                )
                .await;
            }
            continue;
        }

        let id = msg.get("id").unwrap().clone();
        let result = handle_request(
            method,
            &params,
            &state.config,
            &state.tools_cache,
            &google_token,
            &perm_ctx,
        )
        .await;
        let response = build_jsonrpc_response(&id, result);

        if method == "initialize" {
            new_session_id = Some(oauth::generate_secure_token());
        }

        responses.push(response);
    }

    if responses.is_empty() {
        return StatusCode::ACCEPTED.into_response();
    }

    let mut resp_headers = HeaderMap::new();
    if let Some(ref sid) = new_session_id {
        if let Ok(v) = HeaderValue::from_str(sid) {
            resp_headers.insert("mcp-session-id", v);
        }
    } else if let Some(sid) = get_session_id(&headers) {
        if let Ok(v) = HeaderValue::from_str(&sid) {
            resp_headers.insert("mcp-session-id", v);
        }
    }
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let body_str = if is_batch {
        serde_json::to_string(&responses).unwrap()
    } else {
        serde_json::to_string(&responses[0]).unwrap()
    };

    (StatusCode::OK, resp_headers, body_str).into_response()
}

async fn handle_get(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !validate_origin(&headers, &state.allowed_origins) {
        return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
    }
    // OAuth auth on GET /mcp
    if let Err(resp) = resolve_google_token(&headers, &state).await {
        return resp;
    }
    if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
        if !accept.contains("text/event-stream") && !accept.contains("*/*") {
            return (
                StatusCode::NOT_ACCEPTABLE,
                "Accept header must include text/event-stream",
            )
                .into_response();
        }
    }
    let stream = futures_util::stream::pending::<Result<String, std::convert::Infallible>>();
    let body = Body::from_stream(stream);
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(body)
        .unwrap()
}

async fn handle_delete(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !validate_origin(&headers, &state.allowed_origins) {
        return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
    }
    // OAuth auth on DELETE /mcp
    if let Err(resp) = resolve_google_token(&headers, &state).await {
        return resp;
    }
    StatusCode::OK.into_response()
}

// ---- OAuth endpoints ----

/// GET /.well-known/oauth-authorization-server
async fn handle_oauth_metadata(State(state): State<Arc<AppState>>) -> Response {
    let oauth_config = &state.oauth_config;
    let base_url = &oauth_config.base_url;

    let scopes: Vec<&str> = oauth_config.scopes.split_whitespace().collect();

    let metadata = json!({
        "issuer": base_url,
        "authorization_endpoint": format!("{base_url}/authorize"),
        "token_endpoint": format!("{base_url}/token"),
        "registration_endpoint": format!("{base_url}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": scopes
    });

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::to_string(&metadata).unwrap(),
    )
        .into_response()
}

/// GET /authorize — start OAuth flow, redirect to Google.
async fn handle_authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let oauth_config = &state.oauth_config;
    let store = &state.state_store;

    // client_id is required and must be registered.
    let client_id = match params.get("client_id") {
        Some(id) => id.clone(),
        None => {
            return oauth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing client_id",
            );
        }
    };
    let client = match store.get_registered_client(&client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return oauth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_client",
                "Unknown client_id",
            );
        }
        Err(StateStoreError::Unavailable(_)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable",
            )
                .into_response();
        }
        Err(_) => {
            return oauth_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error",
            );
        }
    };

    // redirect_uri must be registered.
    let redirect_uri_param = params.get("redirect_uri");
    match redirect_uri_param {
        Some(uri) if !client.redirect_uris.contains(uri) => {
            return oauth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri not registered for this client",
            );
        }
        None if client.redirect_uris.is_empty() => {
            return oauth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing redirect_uri and no default registered",
            );
        }
        _ => {}
    }

    let redirect_uri = match params.get("redirect_uri") {
        Some(u) => u.clone(),
        None => client.redirect_uris[0].clone(),
    };

    // PKCE is required, S256 only.
    let code_challenge = match params.get("code_challenge") {
        Some(c) => c.clone(),
        None => {
            return oauth_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_challenge is required (PKCE)",
            );
        }
    };
    let code_challenge_method = params
        .get("code_challenge_method")
        .cloned()
        .unwrap_or_else(|| "S256".to_string());
    if code_challenge_method != "S256" {
        return oauth_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Only S256 code_challenge_method is supported",
        );
    }

    let client_state = params.get("state").cloned();

    // Generate our own state for the Google OAuth redirect.
    let our_state = oauth::generate_secure_token();

    let pending = state_store::PendingAuth {
        client_redirect_uri: redirect_uri,
        client_state,
        code_challenge,
        code_challenge_method,
        client_id,
        created_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = store.set_pending_auth(&our_state, &pending).await {
        match e {
            StateStoreError::CapacityExceeded(_) => {
                return oauth_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "Too many pending authorizations",
                );
            }
            StateStoreError::Unavailable(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable",
                )
                    .into_response();
            }
            _ => {
                return oauth_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Internal error",
                );
            }
        }
    }

    let google_url = oauth::build_google_auth_url(oauth_config, &our_state);

    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", google_url)
        .body(Body::empty())
        .unwrap()
}

fn oauth_error_response(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        json!({"error": error, "error_description": description}).to_string(),
    )
        .into_response()
}

/// Build an error redirect back to the client with ?error=...&state=...
fn build_error_redirect(redirect_uri: &str, error: &str, client_state: Option<&str>) -> Response {
    let mut redirect = redirect_uri.to_string();
    let sep = if redirect.contains('?') { "&" } else { "?" };
    let encoded_error =
        percent_encoding::utf8_percent_encode(error, percent_encoding::NON_ALPHANUMERIC);
    redirect.push_str(&format!("{sep}error={encoded_error}"));
    if let Some(cs) = client_state {
        redirect.push_str(&format!(
            "&state={}",
            percent_encoding::utf8_percent_encode(cs, percent_encoding::NON_ALPHANUMERIC)
        ));
    }
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", redirect)
        .body(Body::empty())
        .unwrap()
}

/// GET /oauth/callback — Google redirects here after user consent.
async fn handle_oauth_callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let oauth_config = &state.oauth_config;
    let store = &state.state_store;

    let our_state = match params.get("state") {
        Some(s) => s.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response(),
    };

    // Look up and consume the pending auth.
    let pending = match store.take_pending_auth(&our_state).await {
        Ok(Some(p)) => {
            // TTL check.
            if chrono::Utc::now().timestamp() - p.created_at > state_store::PENDING_AUTH_TTL_SECS {
                return (StatusCode::BAD_REQUEST, "Authorization request expired").into_response();
            }
            p
        }
        Ok(None) => return (StatusCode::BAD_REQUEST, "Unknown or expired state").into_response(),
        Err(StateStoreError::Unavailable(_)) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable",
            )
                .into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    // H-7: Check if Google returned an error (e.g. user denied consent).
    if let Some(error) = params.get("error") {
        return build_error_redirect(
            &pending.client_redirect_uri,
            error,
            pending.client_state.as_deref(),
        );
    }

    let google_code = match params.get("code") {
        Some(c) => c.clone(),
        None => {
            return build_error_redirect(
                &pending.client_redirect_uri,
                "server_error",
                pending.client_state.as_deref(),
            );
        }
    };

    // Exchange Google code for tokens.
    let google_tokens = match oauth::exchange_google_code(oauth_config, &google_code).await {
        Ok(t) => t,
        Err(e) => {
            // H-7: redirect with error on code exchange failure.
            tracing::error!(error = %e, "google token exchange failed");
            return build_error_redirect(
                &pending.client_redirect_uri,
                "server_error",
                pending.client_state.as_deref(),
            );
        }
    };

    // Get user email from Google.
    let email = match oauth::get_google_userinfo(&google_tokens.access_token).await {
        Ok(e) => e,
        Err(e) => {
            // H-7: redirect with error on userinfo failure.
            tracing::error!(error = %e, "failed to get userinfo");
            return build_error_redirect(
                &pending.client_redirect_uri,
                "server_error",
                pending.client_state.as_deref(),
            );
        }
    };

    tracing::info!(email = email.as_str(), "oauth callback: user authenticated");

    // Generate our auth code for the client.
    let our_code = oauth::generate_secure_token();
    let pending_code = state_store::PendingCode {
        email,
        google_tokens,
        code_challenge: pending.code_challenge,
        code_challenge_method: pending.code_challenge_method,
        created_at: chrono::Utc::now().timestamp(),
        redirect_uri: Some(pending.client_redirect_uri.clone()),
        client_id: Some(pending.client_id),
    };
    if let Err(e) = store.set_pending_code(&our_code, &pending_code).await {
        match e {
            StateStoreError::CapacityExceeded(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "Too many pending codes").into_response();
            }
            StateStoreError::Unavailable(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable",
                )
                    .into_response();
            }
            _ => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
            }
        }
    }

    // Redirect back to the client with our auth code (url-encoded).
    let mut redirect = pending.client_redirect_uri;
    let sep = if redirect.contains('?') { "&" } else { "?" };
    let encoded_code =
        percent_encoding::utf8_percent_encode(&our_code, percent_encoding::NON_ALPHANUMERIC);
    redirect.push_str(&format!("{sep}code={encoded_code}"));
    if let Some(cs) = &pending.client_state {
        redirect.push_str(&format!(
            "&state={}",
            percent_encoding::utf8_percent_encode(cs, percent_encoding::NON_ALPHANUMERIC,)
        ));
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", redirect)
        .body(Body::empty())
        .unwrap()
}

/// POST /token — exchange our auth code for a bearer token, or refresh.
async fn handle_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let oauth_config = &state.oauth_config;

    // CORS headers for /token
    let cors_headers = build_cors_headers(&headers, &state.allowed_origins);

    // Parse form-encoded body.
    let params: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();

    let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");

    match grant_type {
        "authorization_code" => {
            handle_token_authorization_code(&state, &params, cors_headers).await
        }
        "refresh_token" => handle_token_refresh(&state, oauth_config, &params, cors_headers).await,
        _ => {
            let mut resp_headers = cors_headers;
            resp_headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            (
                StatusCode::BAD_REQUEST,
                resp_headers,
                json!({"error": "unsupported_grant_type"}).to_string(),
            )
                .into_response()
        }
    }
}

async fn handle_token_authorization_code(
    state: &AppState,
    params: &HashMap<String, String>,
    cors_headers: HeaderMap,
) -> Response {
    let store = &state.state_store;

    let code = match params.get("code") {
        Some(c) => c.clone(),
        None => {
            return token_error_response("invalid_request", "Missing code", cors_headers);
        }
    };

    // Take the pending code (atomic remove).
    let pending_code = match store.take_pending_code(&code).await {
        Ok(Some(pc)) => {
            // Auth code TTL check (10 minutes).
            if chrono::Utc::now().timestamp() - pc.created_at > state_store::AUTH_CODE_TTL_SECS {
                return token_error_response(
                    "invalid_grant",
                    "Authorization code expired",
                    cors_headers,
                );
            }
            pc
        }
        Ok(None) => {
            return token_error_response(
                "invalid_grant",
                "Invalid authorization code",
                cors_headers,
            );
        }
        Err(StateStoreError::Unavailable(_)) => {
            return token_error_response(
                "server_error",
                "Service temporarily unavailable",
                cors_headers,
            );
        }
        Err(_) => {
            return token_error_response("server_error", "Internal error", cors_headers);
        }
    };

    // PKCE validation (always required since code_challenge is mandatory).
    let verifier = match params.get("code_verifier") {
        Some(v) => v,
        None => {
            return token_error_response("invalid_request", "Missing code_verifier", cors_headers);
        }
    };
    if !oauth::validate_pkce(
        verifier,
        &pending_code.code_challenge,
        Some(&pending_code.code_challenge_method),
    ) {
        return token_error_response("invalid_grant", "PKCE validation failed", cors_headers);
    }

    // OAuth 2.1 §4.1.3: If redirect_uri was included in the authorization request,
    // the token request MUST include the same redirect_uri value.
    if let Some(ref expected_redirect_uri) = pending_code.redirect_uri {
        match params.get("redirect_uri") {
            Some(uri) if uri != expected_redirect_uri => {
                return token_error_response(
                    "invalid_grant",
                    "redirect_uri mismatch",
                    cors_headers,
                );
            }
            None => {
                return token_error_response(
                    "invalid_request",
                    "Missing redirect_uri",
                    cors_headers,
                );
            }
            _ => {}
        }
    }

    // OAuth 2.1: Public clients MUST send client_id in token request;
    // it must match the client_id from the authorization request.
    if let Some(ref expected_client_id) = pending_code.client_id {
        match params.get("client_id") {
            Some(cid) if cid != expected_client_id => {
                return token_error_response("invalid_grant", "client_id mismatch", cors_headers);
            }
            None => {
                return token_error_response("invalid_request", "Missing client_id", cors_headers);
            }
            _ => {}
        }
    }

    // Issue bearer token and refresh token with 256-bit entropy each.
    let bearer_token = oauth::generate_secure_token();
    let refresh_token = oauth::generate_secure_token();
    let now = chrono::Utc::now().timestamp();
    let bearer_expires_at = now + state_store::BEARER_TOKEN_LIFETIME_SECS;
    let refresh_expires_at = now + state_store::REFRESH_TOKEN_LIFETIME_SECS;

    // H-6: Atomic transaction — create user_session, bearer_session, refresh_token.
    let input = state_store::CodeExchangeInput {
        auth_code: code,
        email: pending_code.email,
        google_tokens: pending_code.google_tokens,
        bearer_token: bearer_token.clone(),
        bearer_expires_at,
        refresh_token: refresh_token.clone(),
        refresh_expires_at,
    };
    if let Err(e) = store.exchange_code_transaction(input).await {
        match e {
            StateStoreError::CapacityExceeded(_) => {
                return token_error_response(
                    "server_error",
                    "Too many active sessions",
                    cors_headers,
                );
            }
            StateStoreError::Unavailable(_) => {
                return token_error_response(
                    "server_error",
                    "Service temporarily unavailable",
                    cors_headers,
                );
            }
            _ => {
                tracing::error!(error = %e, "code exchange transaction failed");
                return token_error_response("server_error", "Internal error", cors_headers);
            }
        }
    }

    let mut resp_headers = cors_headers;
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp_headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    let resp_body = json!({
        "access_token": bearer_token,
        "token_type": "Bearer",
        "expires_in": state_store::BEARER_TOKEN_LIFETIME_SECS,
        "refresh_token": refresh_token,
    });

    (
        StatusCode::OK,
        resp_headers,
        serde_json::to_string(&resp_body).unwrap(),
    )
        .into_response()
}

async fn handle_token_refresh(
    state: &AppState,
    oauth_config: &oauth::OAuthConfig,
    params: &HashMap<String, String>,
    cors_headers: HeaderMap,
) -> Response {
    let store = &state.state_store;

    let old_refresh = match params.get("refresh_token") {
        Some(t) => t.clone(),
        None => {
            return token_error_response("invalid_request", "Missing refresh_token", cors_headers);
        }
    };

    // Look up the refresh token entry.
    let refresh_entry = match store.get_refresh_entry(&old_refresh).await {
        Ok(Some(entry)) => {
            // H-3: Check refresh token expiry.
            if chrono::Utc::now().timestamp() >= entry.refresh_expires_at {
                let _ = store.delete_refresh_entry(&old_refresh).await;
                return token_error_response(
                    "invalid_grant",
                    "Refresh token expired",
                    cors_headers,
                );
            }
            entry
        }
        Ok(None) => {
            return token_error_response("invalid_grant", "Unknown refresh token", cors_headers);
        }
        Err(StateStoreError::Unavailable(_)) => {
            return token_error_response(
                "server_error",
                "Service temporarily unavailable",
                cors_headers,
            );
        }
        Err(_) => {
            return token_error_response("server_error", "Internal error", cors_headers);
        }
    };

    let email = &refresh_entry.email;

    // Look up the user session to check if Google token refresh is needed.
    let user_session = match store.get_user_session(email).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            // User session gone — treat as invalid_grant.
            let _ = store.delete_refresh_entry(&old_refresh).await;
            return token_error_response("invalid_grant", "Session expired", cors_headers);
        }
        Err(_) => {
            return token_error_response("server_error", "Internal error", cors_headers);
        }
    };

    // Refresh Google token if needed.
    let updated_google_tokens = if user_session.google_tokens.is_expired() {
        let rt = match &user_session.google_tokens.refresh_token {
            Some(rt) => rt.clone(),
            None => {
                return token_error_response(
                    "invalid_grant",
                    "No Google refresh token available",
                    cors_headers,
                );
            }
        };
        match oauth::refresh_google_token(oauth_config, &rt).await {
            Ok(new_tokens) => Some(new_tokens),
            Err(e) => {
                // H-5: On Google invalid_grant, invalidate the session.
                if e.to_string().contains("invalid_grant") {
                    tracing::warn!(
                        email = email,
                        "Google refresh token invalid, invalidating session"
                    );
                    let _ = store.delete_user_session(email).await;
                    let _ = store.delete_refresh_entry(&old_refresh).await;
                    if let Some(ref bt) = refresh_entry.bearer_token {
                        let _ = store.delete_bearer_session_by_stored_key(bt).await;
                    }
                    return token_error_response(
                        "invalid_grant",
                        "Google token revoked, please re-authorize",
                        cors_headers,
                    );
                }
                return token_error_response(
                    "invalid_grant",
                    "Failed to refresh Google token",
                    cors_headers,
                );
            }
        }
    } else {
        None
    };

    // Issue new bearer token and new refresh token.
    let new_bearer = oauth::generate_secure_token();
    let new_refresh = oauth::generate_secure_token();
    let now = chrono::Utc::now().timestamp();
    let bearer_expires_at = now + state_store::BEARER_TOKEN_LIFETIME_SECS;
    let refresh_expires_at = now + state_store::REFRESH_TOKEN_LIFETIME_SECS;

    // Use the bearer token stored in the refresh entry to invalidate the old session.
    let old_bearer_token = refresh_entry.bearer_token.clone();

    // H-6: Atomic transaction — rotate bearer + refresh tokens.
    let input = state_store::RefreshTransactionInput {
        old_refresh_token: old_refresh,
        old_bearer_token,
        email: email.clone(),
        new_bearer_token: new_bearer.clone(),
        bearer_expires_at,
        new_refresh_token: new_refresh.clone(),
        refresh_expires_at,
        updated_google_tokens,
    };
    if let Err(e) = store.refresh_token_transaction(input).await {
        match e {
            StateStoreError::CapacityExceeded(_) => {
                return token_error_response(
                    "server_error",
                    "Too many active sessions",
                    cors_headers,
                );
            }
            StateStoreError::Unavailable(_) => {
                return token_error_response(
                    "server_error",
                    "Service temporarily unavailable",
                    cors_headers,
                );
            }
            _ => {
                tracing::error!(error = %e, "refresh token transaction failed");
                return token_error_response("server_error", "Internal error", cors_headers);
            }
        }
    }

    let mut resp_headers = cors_headers;
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp_headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    let resp_body = json!({
        "access_token": new_bearer,
        "token_type": "Bearer",
        "expires_in": state_store::BEARER_TOKEN_LIFETIME_SECS,
        "refresh_token": new_refresh,
    });

    (
        StatusCode::OK,
        resp_headers,
        serde_json::to_string(&resp_body).unwrap(),
    )
        .into_response()
}

fn token_error_response(error: &str, description: &str, cors_headers: HeaderMap) -> Response {
    let status = if error == "server_error" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut resp_headers = cors_headers;
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (
        status,
        resp_headers,
        json!({"error": error, "error_description": description}).to_string(),
    )
        .into_response()
}

/// POST /register — Dynamic Client Registration (RFC 7591).
async fn handle_register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let store = &state.state_store;
    let cors_headers = build_cors_headers(&headers, &state.allowed_origins);

    #[derive(serde::Deserialize)]
    struct RegistrationRequest {
        #[serde(default)]
        client_name: Option<String>,
        #[serde(default)]
        redirect_uris: Vec<String>,
        #[serde(default)]
        grant_types: Option<Vec<String>>,
        #[serde(default)]
        response_types: Option<Vec<String>>,
    }

    let req: RegistrationRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid registration request").into_response(),
    };

    // Validate redirect_uri schemes.
    for uri in &req.redirect_uris {
        if let Err(e) = oauth::validate_redirect_uri(uri) {
            let mut resp_headers = cors_headers;
            resp_headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return (
                StatusCode::BAD_REQUEST,
                resp_headers,
                json!({"error": "invalid_redirect_uri", "error_description": e}).to_string(),
            )
                .into_response();
        }
    }

    let client_id = oauth::generate_secure_token();
    let now = chrono::Utc::now().timestamp();
    let client = state_store::RegisteredClient {
        client_id: client_id.clone(),
        redirect_uris: req.redirect_uris.clone(),
        client_name: req.client_name.clone(),
        client_id_issued_at: now,
    };

    if let Err(e) = store.set_registered_client(&client_id, &client).await {
        match e {
            StateStoreError::CapacityExceeded(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Too many registered clients",
                )
                    .into_response();
            }
            StateStoreError::Unavailable(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable",
                )
                    .into_response();
            }
            _ => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
            }
        }
    }

    let mut resp_headers = cors_headers;
    resp_headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let resp_body = json!({
        "client_id": client_id,
        "client_name": req.client_name,
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types.unwrap_or_else(|| vec!["authorization_code".to_string()]),
        "response_types": req.response_types.unwrap_or_else(|| vec!["code".to_string()]),
        "token_endpoint_auth_method": "none",
        "client_id_issued_at": now
    });

    (
        StatusCode::CREATED,
        resp_headers,
        serde_json::to_string(&resp_body).unwrap(),
    )
        .into_response()
}

/// Handle CORS preflight (OPTIONS) requests for OAuth endpoints.
async fn handle_cors_preflight(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let cors_headers = build_cors_headers(&headers, &state.allowed_origins);
    (StatusCode::NO_CONTENT, cors_headers).into_response()
}

/// Build CORS response headers for OAuth endpoints.
fn build_cors_headers(req_headers: &HeaderMap, allowed_origins: &[String]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(origin) = req_headers.get("origin").and_then(|v| v.to_str().ok()) {
        let allowed = if allowed_origins.is_empty() {
            let lower = origin.to_lowercase();
            is_localhost_origin(&lower)
        } else {
            allowed_origins.iter().any(|a| a == origin)
        };
        if allowed {
            if let Ok(val) = HeaderValue::from_str(origin) {
                headers.insert("access-control-allow-origin", val);
            }
            headers.insert(
                "access-control-allow-methods",
                HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
            );
            headers.insert(
                "access-control-allow-headers",
                HeaderValue::from_static("Content-Type, Authorization, Mcp-Session-Id, Accept"),
            );
        }
    }
    headers
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use tower::ServiceExt;

    const ACCEPT_MCP: &str = "application/json, text/event-stream";
    const TEST_BEARER: &str = "test-bearer-token";

    fn test_oauth_config() -> OAuthConfig {
        OAuthConfig {
            client_id: "test-client-id".to_string(),
            client_secret: "test-secret".to_string(),
            base_url: "https://gw.example.com".to_string(),
            scopes: "openid email".to_string(),
        }
    }

    async fn make_test_store() -> Arc<dyn StateStore> {
        let store: Arc<dyn StateStore> = Arc::new(state_store::InMemoryStateStore::new());
        // Pre-register a bearer session and user session for tests that need auth.
        let user_session = state_store::UserSessionData {
            google_tokens: oauth::GoogleTokens {
                access_token: "google-at".to_string(),
                refresh_token: None,
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
        };
        store
            .set_user_session("user@corp.com", &user_session)
            .await
            .unwrap();
        let bearer_session = state_store::BearerSession {
            email: "user@corp.com".to_string(),
            bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
        };
        store
            .set_bearer_session(TEST_BEARER, &bearer_session)
            .await
            .unwrap();
        store
    }

    async fn test_state() -> Arc<AppState> {
        test_state_with_origins(vec![]).await
    }

    async fn test_state_with_origins(allowed_origins: Vec<String>) -> Arc<AppState> {
        let store = make_test_store().await;
        Arc::new(AppState {
            config: ServerConfig {
                services: vec![],
                workflows: false,
                _helpers: false,
                tool_mode: ToolMode::Full,
            },
            tools_cache: Mutex::new(None),
            allowed_origins,
            oauth_config: test_oauth_config(),
            state_store: store,
            permissions: None,
        })
    }

    async fn test_state_with_oauth() -> Arc<AppState> {
        test_state().await
    }

    fn test_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/mcp", post(handle_post))
            .route("/mcp", get(handle_get))
            .route("/mcp", delete(handle_delete))
            .route(
                "/.well-known/oauth-authorization-server",
                get(handle_oauth_metadata),
            )
            .route("/authorize", get(handle_authorize))
            .route("/oauth/callback", get(handle_oauth_callback))
            .route("/token", post(handle_token).options(handle_cors_preflight))
            .route(
                "/register",
                post(handle_register).options(handle_cors_preflight),
            )
            .with_state(state)
    }

    async fn init_session(app: &Router) -> String {
        init_session_with_bearer(app, TEST_BEARER).await
    }

    async fn init_session_with_bearer(app: &Router, bearer: &str) -> String {
        let init_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::from(serde_json::to_string(&init_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    // --- MCP transport tests ---

    #[tokio::test]
    async fn test_initialize_returns_session_id() {
        let state = test_state().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("mcp-session-id").is_some());
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["result"]["protocolVersion"], "2024-11-05");
    }

    #[tokio::test]
    async fn test_tools_list_without_session_id() {
        let state = test_state().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tools_list_with_valid_session() {
        let state = test_state().await;
        let app = test_app(state);
        let session_id = init_session(&app).await;
        let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", &session_id)
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result["result"]["tools"].is_array());
    }

    #[tokio::test]
    async fn test_delete_session() {
        let state = test_state().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_notification_returns_accepted() {
        let state = test_state().await;
        let app = test_app(state);
        let session_id = init_session(&app).await;
        let body = json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", &session_id)
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_parse_error() {
        let state = test_state().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::from("not valid json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn test_delete_without_session_header() {
        let state = test_state().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_delete_unknown_session() {
        let state = test_state().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", "nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_batch_request() {
        let state = test_state().await;
        let app = test_app(state);
        let session_id = init_session(&app).await;
        let batch = json!([
            {"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}},
            {"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
        ]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", &session_id)
                    .body(Body::from(serde_json::to_string(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result.is_array());
        assert_eq!(result.as_array().unwrap().len(), 1);
        assert_eq!(result[0]["id"], 10);
    }

    #[tokio::test]
    async fn test_batch_all_notifications_returns_accepted() {
        let state = test_state().await;
        let app = test_app(state);
        let session_id = init_session(&app).await;
        let batch = json!([{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", &session_id)
                    .body(Body::from(serde_json::to_string(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_origin_validation_rejects_bad_origin() {
        let state = test_state().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("origin", "https://evil.example.com")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_origin_validation_allows_localhost() {
        let state = test_state().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("origin", "http://localhost:3000")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_origin_validation_allows_configured_origin() {
        let state = test_state_with_origins(vec!["https://my-app.example.com".to_string()]).await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("origin", "https://my-app.example.com")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_accept_header_missing_event_stream() {
        let state = test_state().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn test_get_requires_accept_event_stream() {
        let state = test_state().await;
        let app = test_app(state);
        let session_id = init_session(&app).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("accept", "application/json")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .header("mcp-session-id", &session_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
    }

    // --- OAuth endpoint tests ---

    /// Helper: register a client and return the client_id.
    async fn register_client(app: &Router, redirect_uris: &[&str]) -> String {
        let body = json!({
            "client_name": "TestClient",
            "redirect_uris": redirect_uris
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        result["client_id"].as_str().unwrap().to_string()
    }

    async fn make_pending_code(store: &Arc<dyn StateStore>, code: &str, challenge: String) {
        let pc = state_store::PendingCode {
            email: "user@test.com".to_string(),
            google_tokens: oauth::GoogleTokens {
                access_token: "google-at".to_string(),
                refresh_token: Some("google-rt".to_string()),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
            code_challenge: challenge,
            code_challenge_method: "S256".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            client_id: Some("test-client-id".to_string()),
        };
        store.set_pending_code(code, &pc).await.unwrap();
    }

    #[tokio::test]
    async fn test_oauth_metadata_returns_endpoints() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let meta: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(meta["issuer"], "https://gw.example.com");
        assert_eq!(
            meta["authorization_endpoint"],
            "https://gw.example.com/authorize"
        );
        assert_eq!(meta["token_endpoint"], "https://gw.example.com/token");
        assert!(meta["scopes_supported"].is_array());
        let grant_types = meta["grant_types_supported"].as_array().unwrap();
        assert!(grant_types.contains(&json!("refresh_token")));
    }

    #[tokio::test]
    async fn test_authorize_requires_client_id() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/authorize?redirect_uri=https://x.com/cb&code_challenge=xyz&code_challenge_method=S256")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_authorize_requires_pkce() {
        let state = test_state_with_oauth().await;
        let app = test_app(state.clone());
        let client_id = register_client(&app, &["https://x.com/cb"]).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!(
                        "/authorize?client_id={client_id}&redirect_uri=https://x.com/cb"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["error_description"]
            .as_str()
            .unwrap()
            .contains("code_challenge"));
    }

    #[tokio::test]
    async fn test_authorize_rejects_plain_pkce() {
        let state = test_state_with_oauth().await;
        let app = test_app(state.clone());
        let client_id = register_client(&app, &["https://x.com/cb"]).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/authorize?client_id={client_id}&redirect_uri=https://x.com/cb&code_challenge=xyz&code_challenge_method=plain"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_validates_redirect_uri() {
        let state = test_state_with_oauth().await;
        let app = test_app(state.clone());
        let client_id = register_client(&app, &["https://registered.com/cb"]).await;
        // Try with unregistered redirect_uri
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/authorize?client_id={client_id}&redirect_uri=https://evil.com/cb&code_challenge=xyz&code_challenge_method=S256"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_authorize_redirects_to_google() {
        let state = test_state_with_oauth().await;
        let app = test_app(state.clone());
        let client_id = register_client(&app, &["https://client.example.com/cb"]).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/authorize?client_id={client_id}&redirect_uri=https://client.example.com/cb&state=abc&code_challenge=xyz&code_challenge_method=S256"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://accounts.google.com/o/oauth2/auth"));
        assert!(location.contains("client_id=test-client-id"));
    }

    #[tokio::test]
    async fn test_token_invalid_grant_type() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_token_invalid_code() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=authorization_code&code=bogus&code_verifier=x",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_with_pkce() {
        let state = test_state_with_oauth().await;
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(verifier.as_bytes());
            oauth::base64_url_encode(&digest)
        };

        make_pending_code(&state.state_store, "test-code", challenge).await;

        let app = test_app(state.clone());
        let body_str = format!(
            "grant_type=authorization_code&code=test-code&code_verifier={verifier}&redirect_uri=http://localhost:3000/callback&client_id=test-client-id"
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body_str))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["token_type"], "Bearer");
        assert!(result["expires_in"].as_i64().unwrap() > 0);
        assert!(result["access_token"].as_str().is_some());
        assert!(result["refresh_token"].as_str().is_some());

        let bearer = result["access_token"].as_str().unwrap();
        let refresh = result["refresh_token"].as_str().unwrap();
        // access_token and refresh_token must be distinct values.
        assert_ne!(bearer, refresh);

        // Verify bearer_session was created.
        let bearer_session = state
            .state_store
            .get_bearer_session(bearer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bearer_session.email, "user@test.com");
        // Verify refresh_token entry was created.
        let refresh_entry = state
            .state_store
            .get_refresh_entry(refresh)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refresh_entry.email, "user@test.com");
    }

    #[tokio::test]
    async fn test_token_exchange_expired_code() {
        let state = test_state_with_oauth().await;
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(verifier.as_bytes());
            oauth::base64_url_encode(&digest)
        };
        // Insert an expired pending code.
        let pc = state_store::PendingCode {
            email: "user@test.com".to_string(),
            google_tokens: oauth::GoogleTokens {
                access_token: "google-at".to_string(),
                refresh_token: Some("google-rt".to_string()),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
            code_challenge: challenge,
            code_challenge_method: "S256".to_string(),
            created_at: chrono::Utc::now().timestamp() - 700, // expired (>600s)
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            client_id: Some("test-client-id".to_string()),
        };
        state
            .state_store
            .set_pending_code("expired-code", &pc)
            .await
            .unwrap();

        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code=expired-code&code_verifier={verifier}&redirect_uri=http://localhost:3000/callback&client_id=test-client-id"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_token_exchange_pkce_failure() {
        let state = test_state_with_oauth().await;
        make_pending_code(
            &state.state_store,
            "code2",
            "expected-challenge".to_string(),
        )
        .await;

        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "grant_type=authorization_code&code=code2&code_verifier=wrong",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(body["error_description"].as_str().unwrap().contains("PKCE"));
    }

    #[tokio::test]
    async fn test_refresh_token_grant() {
        let state = test_state_with_oauth().await;
        let store = &state.state_store;
        // Set up a user session, bearer session, and refresh token.
        let user_session = state_store::UserSessionData {
            google_tokens: oauth::GoogleTokens {
                access_token: "google-at".to_string(),
                refresh_token: None,
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
        };
        store
            .set_user_session("user@corp.com", &user_session)
            .await
            .unwrap();
        let old_bearer = "old-bearer-tok";
        let old_refresh = "old-refresh-tok";
        let bearer_session = state_store::BearerSession {
            email: "user@corp.com".to_string(),
            bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
        };
        store
            .set_bearer_session(old_bearer, &bearer_session)
            .await
            .unwrap();
        let refresh_entry = state_store::RefreshTokenEntry {
            email: "user@corp.com".to_string(),
            refresh_expires_at: chrono::Utc::now().timestamp()
                + state_store::REFRESH_TOKEN_LIFETIME_SECS,
            bearer_token: Some(old_bearer.to_string()),
        };
        store
            .set_refresh_entry(old_refresh, &refresh_entry)
            .await
            .unwrap();

        let app = test_app(state.clone());
        let body_str = format!("grant_type=refresh_token&refresh_token={old_refresh}");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body_str))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();

        let new_bearer = result["access_token"].as_str().unwrap();
        let new_refresh = result["refresh_token"].as_str().unwrap();

        // New tokens must differ from old ones.
        assert_ne!(new_bearer, old_bearer);
        assert_ne!(new_refresh, old_refresh);
        // access_token and refresh_token must be distinct.
        assert_ne!(new_bearer, new_refresh);

        // Old refresh must be removed.
        assert!(store
            .get_refresh_entry(old_refresh)
            .await
            .unwrap()
            .is_none());
        // New ones must exist.
        assert!(store
            .get_bearer_session(new_bearer)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_refresh_entry(new_refresh)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_refresh_token_unknown() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=refresh_token&refresh_token=bogus"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_register_returns_client_id() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let body = json!({
            "client_name": "Claude",
            "redirect_uris": ["https://claude.ai/callback"]
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(result["client_id"].as_str().is_some());
        assert_eq!(result["client_name"], "Claude");
        assert!(result["client_id_issued_at"].as_i64().is_some());
    }

    #[tokio::test]
    async fn test_register_rejects_dangerous_redirect_uri() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let body = json!({
            "client_name": "Evil",
            "redirect_uris": ["javascript:alert(1)"]
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_mcp_post_requires_auth_when_oauth_enabled() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get("www-authenticate").is_some());
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("https://gw.example.com/.well-known/oauth-authorization-server"));
    }

    #[tokio::test]
    async fn test_mcp_post_with_valid_bearer_token() {
        let state = test_state_with_oauth().await;
        // Add a second bearer session
        let user_session = state_store::UserSessionData {
            google_tokens: oauth::GoogleTokens {
                access_token: "google-at".to_string(),
                refresh_token: None,
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            },
        };
        state
            .state_store
            .set_user_session("user@corp.com", &user_session)
            .await
            .unwrap();
        let bearer_session = state_store::BearerSession {
            email: "user@corp.com".to_string(),
            bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
        };
        state
            .state_store
            .set_bearer_session("valid-bearer", &bearer_session)
            .await
            .unwrap();

        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", "Bearer valid-bearer")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("mcp-session-id").is_some());
    }

    #[tokio::test]
    async fn test_mcp_post_with_invalid_bearer_token() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .header("accept", ACCEPT_MCP)
                    .header("authorization", "Bearer invalid-token")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_mcp_requires_auth_when_oauth_enabled() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("accept", "text/event-stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_mcp_requires_auth_when_oauth_enabled() {
        let state = test_state_with_oauth().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/mcp")
                    .header("mcp-session-id", "some-session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
