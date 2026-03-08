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

//! Model Context Protocol (MCP) server implementation.
//! Provides both stdio and Streamable HTTP transports exposing Google Workspace APIs as MCP tools.

pub(crate) mod oauth;

use crate::discovery::RestResource;
use crate::error::GwsError;
use crate::services;
use clap::{Arg, Command};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    pub services: Vec<String>,
    pub workflows: bool,
    pub _helpers: bool,
}

fn build_mcp_cli() -> Command {
    Command::new("mcp")
        .about("Starts the MCP server (stdio or HTTP)")
        .arg(
            Arg::new("services")
                .long("services")
                .short('s')
                .help("Comma separated list of services to expose (e.g., drive,gmail,all)")
                .default_value(""),
        )
        .arg(
            Arg::new("workflows")
                .long("workflows")
                .short('w')
                .action(clap::ArgAction::SetTrue)
                .help("Expose workflows as tools"),
        )
        .arg(
            Arg::new("helpers")
                .long("helpers")
                .short('e')
                .action(clap::ArgAction::SetTrue)
                .help("Expose service-specific helpers as tools"),
        )
        .arg(
            Arg::new("transport")
                .long("transport")
                .short('t')
                .help("Transport mode: stdio or http")
                .default_value("stdio")
                .value_parser(["stdio", "http"]),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .help("Port for HTTP transport")
                .default_value("8080")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("host")
                .long("host")
                .help("Host address to bind for HTTP transport (use 0.0.0.0 for all interfaces)")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("allow-origin")
                .long("allow-origin")
                .help("Allowed Origin header values (comma-separated). If unset, localhost origins are allowed by default.")
                .default_value(""),
        )
        .arg(
            Arg::new("oauth-client-id")
                .long("oauth-client-id")
                .help("Google OAuth client ID for gateway auth (env: GWS_OAUTH_CLIENT_ID)")
                .env("GWS_OAUTH_CLIENT_ID"),
        )
        .arg(
            Arg::new("oauth-client-secret")
                .help("Google OAuth client secret (env only, not accepted as CLI arg)")
                .env("GWS_OAUTH_CLIENT_SECRET")
                .hide(true),
        )
        .arg(
            Arg::new("gateway-base-url")
                .long("gateway-base-url")
                .help("Public base URL of this gateway (env: GWS_GATEWAY_BASE_URL)")
                .env("GWS_GATEWAY_BASE_URL"),
        )
        .arg(
            Arg::new("oauth-scopes")
                .long("oauth-scopes")
                .help("Space-separated OAuth scopes (env: GWS_OAUTH_SCOPES)")
                .env("GWS_OAUTH_SCOPES")
                .default_value(oauth::DEFAULT_OAUTH_SCOPES),
        )
}

fn parse_server_config(matches: &clap::ArgMatches) -> ServerConfig {
    let mut config = ServerConfig {
        services: Vec::new(),
        workflows: matches.get_flag("workflows"),
        _helpers: matches.get_flag("helpers"),
    };

    let svc_str = matches.get_one::<String>("services").unwrap();
    if !svc_str.is_empty() {
        if svc_str == "all" {
            config.services = services::SERVICES
                .iter()
                .map(|s| s.aliases[0].to_string())
                .collect();
        } else {
            config.services = svc_str.split(',').map(|s| s.trim().to_string()).collect();
        }
    }

    config
}

pub async fn start(args: &[String]) -> Result<(), GwsError> {
    let matches = build_mcp_cli().get_matches_from(args);
    let config = parse_server_config(&matches);

    if config.services.is_empty() {
        eprintln!("[gws mcp] Warning: No services configured. Zero tools will be exposed.");
        eprintln!("[gws mcp] Re-run with: gws mcp -s <service> (e.g., -s drive,gmail,calendar)");
        eprintln!("[gws mcp] Use -s all to expose all available services.");
    } else {
        eprintln!(
            "[gws mcp] Starting with services: {}",
            config.services.join(", ")
        );
    }

    let transport = matches.get_one::<String>("transport").unwrap().as_str();

    // Parse optional OAuth config (all three fields required to enable)
    let oauth_config = match (
        matches.get_one::<String>("oauth-client-id"),
        matches.get_one::<String>("oauth-client-secret"),
        matches.get_one::<String>("gateway-base-url"),
    ) {
        (Some(client_id), Some(client_secret), Some(base_url)) => {
            let base_url = base_url.trim_end_matches('/').to_string();
            oauth::validate_gateway_base_url(&base_url).map_err(|e| {
                GwsError::Validation(e)
            })?;
            let scopes = matches
                .get_one::<String>("oauth-scopes")
                .unwrap()
                .clone();
            eprintln!("[gws mcp] OAuth enabled for gateway auth");
            Some(oauth::OAuthConfig {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                base_url,
                scopes,
            })
        }
        (None, None, None) => None,
        _ => {
            return Err(GwsError::Validation(
                "OAuth requires all three: --oauth-client-id, --oauth-client-secret, --gateway-base-url".to_string(),
            ));
        }
    };

    match transport {
        "http" => {
            let port = *matches.get_one::<u16>("port").unwrap();
            let host = matches.get_one::<String>("host").unwrap().clone();
            let allow_origin = matches
                .get_one::<String>("allow-origin")
                .unwrap()
                .clone();
            eprintln!("[gws mcp] Starting HTTP transport on {host}:{port}");
            http_transport::serve(config, &host, port, &allow_origin, oauth_config).await
        }
        _ => {
            eprintln!("[gws mcp] Starting stdio transport");
            stdio_transport::serve(config).await
        }
    }
}

// --- Shared request handler ---

/// Handle a JSON-RPC MCP request.
///
/// `access_token` is an optional pre-authenticated Google OAuth access token.
/// When provided (gateway mode), it is used for API calls instead of local credentials.
pub(crate) async fn handle_request(
    method: &str,
    params: &Value,
    config: &ServerConfig,
    tools_cache: &Mutex<Option<Vec<Value>>>,
    access_token: Option<&str>,
) -> Result<Value, GwsError> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "gws-mcp",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": {
                "tools": {}
            }
        })),
        "notifications/initialized" => Ok(json!({})),
        "tools/list" => {
            let mut cache = tools_cache.lock().await;
            if cache.is_none() {
                *cache = Some(build_tools_list(config).await?);
            }
            Ok(json!({
                "tools": cache.as_ref().unwrap()
            }))
        }
        "tools/call" => handle_tools_call(params, config, access_token).await,
        _ => Err(GwsError::Validation(format!(
            "Method not supported: {}",
            method
        ))),
    }
}

pub(crate) fn build_jsonrpc_response(id: &Value, result: Result<Value, GwsError>) -> Value {
    match result {
        Ok(res) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": res
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": e.to_string()
            }
        }),
    }
}

pub(crate) fn build_parse_error_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": -32700,
            "message": "Parse error"
        }
    })
}

// --- stdio transport ---

mod stdio_transport {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    pub async fn serve(config: ServerConfig) -> Result<(), GwsError> {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        let mut stdout = tokio::io::stdout();
        let tools_cache = Mutex::new(None);

        while let Ok(Some(line)) = stdin.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            let response = match serde_json::from_str::<Value>(&line) {
                Ok(req) => {
                    let is_notification = req.get("id").is_none();
                    if is_notification {
                        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                        let _ = handle_request(method, &params, &config, &tools_cache, None).await;
                        continue;
                    }

                    let id = req.get("id").unwrap().clone();
                    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                    let result = handle_request(method, &params, &config, &tools_cache, None).await;
                    build_jsonrpc_response(&id, result)
                }
                Err(_) => build_parse_error_response(),
            };

            let mut out = match serde_json::to_string(&response) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[gws mcp] Failed to serialize response: {e}");
                    continue;
                }
            };
            out.push('\n');
            let _ = stdout.write_all(out.as_bytes()).await;
            let _ = stdout.flush().await;
        }

        Ok(())
    }
}

// --- HTTP (Streamable HTTP) transport ---

mod http_transport {
    use super::oauth::{self, OAuthConfig, TokenStore};
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
        /// Maps session_id -> bearer_token (or empty string when OAuth is disabled).
        sessions: Mutex<HashMap<String, String>>,
        allowed_origins: Vec<String>,
        oauth_config: Option<OAuthConfig>,
        token_store: Mutex<TokenStore>,
    }

    pub async fn serve(
        config: ServerConfig,
        host: &str,
        port: u16,
        allow_origin: &str,
        oauth_config: Option<OAuthConfig>,
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
            sessions: Mutex::new(HashMap::new()),
            allowed_origins,
            oauth_config,
            token_store: Mutex::new(TokenStore::new()),
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
            .route("/token", post(handle_token))
            .route("/register", post(handle_register))
            .with_state(state);

        let addr: std::net::SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| GwsError::Other(anyhow::anyhow!("Invalid host address: {e}")))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| GwsError::Other(anyhow::anyhow!("Failed to bind to {addr}: {e}")))?;

        eprintln!("[gws mcp] HTTP server listening on http://{addr}/mcp");

        axum::serve(listener, app)
            .await
            .map_err(|e| GwsError::Other(anyhow::anyhow!("HTTP server error: {e}")))?;

        Ok(())
    }

    // ---- helpers ----

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
        lower.starts_with("http://localhost")
            || lower.starts_with("https://localhost")
            || lower.starts_with("http://127.0.0.1")
            || lower.starts_with("https://127.0.0.1")
            || lower.starts_with("http://[::1]")
            || lower.starts_with("https://[::1]")
    }

    async fn validate_session(
        headers: &HeaderMap,
        sessions: &Mutex<HashMap<String, String>>,
        oauth_enabled: bool,
    ) -> Result<String, Response> {
        match get_session_id(headers) {
            Some(id) => {
                let sessions = sessions.lock().await;
                match sessions.get(&id) {
                    Some(bound_bearer) => {
                        // When OAuth is enabled, verify the bearer token matches the one
                        // that created this session.
                        if oauth_enabled {
                            let bearer = extract_bearer_token(headers).unwrap_or_default();
                            if bearer != *bound_bearer {
                                return Err((
                                    StatusCode::FORBIDDEN,
                                    "Bearer token does not match session owner",
                                )
                                    .into_response());
                            }
                        }
                        Ok(id)
                    }
                    None => Err(
                        (StatusCode::NOT_FOUND, "Session not found or expired").into_response()
                    ),
                }
            }
            None => {
                Err((StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header").into_response())
            }
        }
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
    /// If OAuth is configured, requires a valid bearer token and refreshes if needed.
    /// Returns `None` if OAuth is not configured (local mode).
    /// Returns `Err(Response)` with 401 if auth is required but missing/invalid.
    fn www_authenticate_header(state: &AppState) -> String {
        let base_url = state
            .oauth_config
            .as_ref()
            .map(|c| c.base_url.as_str())
            .unwrap_or("");
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

    async fn resolve_google_token(
        headers: &HeaderMap,
        state: &AppState,
    ) -> Result<Option<String>, Response> {
        let oauth_config = match &state.oauth_config {
            Some(c) => c,
            None => return Ok(None), // No OAuth → local mode
        };

        let bearer = extract_bearer_token(headers)
            .ok_or_else(|| unauthorized_response(state, "Authentication required"))?;

        match oauth::get_valid_google_token(oauth_config, &state.token_store, &bearer).await {
            Ok(token) => Ok(Some(token)),
            Err(_) => Err(unauthorized_response(state, "Invalid or expired token")),
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

        // Resolve Google token (returns 401 if OAuth enabled but no valid bearer)
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

        let has_initialize = messages
            .iter()
            .any(|m| m.get("method").and_then(|v| v.as_str()) == Some("initialize"));

        if !has_initialize {
            if let Err(resp) =
                validate_session(&headers, &state.sessions, state.oauth_config.is_some()).await
            {
                return resp;
            }
        }

        // Extract bearer token for session binding (empty string when OAuth disabled).
        let bearer_for_binding = extract_bearer_token(&headers).unwrap_or_default();

        let mut responses = Vec::new();
        let mut new_session_id: Option<String> = None;

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
                        google_token.as_deref(),
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
                google_token.as_deref(),
            )
            .await;
            let response = build_jsonrpc_response(&id, result);

            if method == "initialize" {
                let session_id = oauth::generate_secure_token();
                state
                    .sessions
                    .lock()
                    .await
                    .insert(session_id.clone(), bearer_for_binding.clone());
                new_session_id = Some(session_id);
            }

            responses.push(response);
        }

        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }

        let mut resp_headers = HeaderMap::new();
        if let Some(ref sid) = new_session_id {
            resp_headers.insert("mcp-session-id", HeaderValue::from_str(sid).unwrap());
        } else if let Some(sid) = get_session_id(&headers) {
            resp_headers.insert("mcp-session-id", HeaderValue::from_str(&sid).unwrap());
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

    async fn handle_get(
        State(state): State<Arc<AppState>>,
        headers: HeaderMap,
    ) -> Response {
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
        if let Err(resp) =
            validate_session(&headers, &state.sessions, state.oauth_config.is_some()).await
        {
            return resp;
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

    async fn handle_delete(
        State(state): State<Arc<AppState>>,
        headers: HeaderMap,
    ) -> Response {
        if !validate_origin(&headers, &state.allowed_origins) {
            return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
        }
        // OAuth auth on DELETE /mcp
        if let Err(resp) = resolve_google_token(&headers, &state).await {
            return resp;
        }
        // Validate session exists and bearer matches owner.
        match validate_session(&headers, &state.sessions, state.oauth_config.is_some()).await {
            Ok(id) => {
                let mut sessions = state.sessions.lock().await;
                sessions.remove(&id);
                StatusCode::OK.into_response()
            }
            Err(resp) => resp,
        }
    }

    // ---- OAuth endpoints ----

    /// GET /.well-known/oauth-authorization-server
    async fn handle_oauth_metadata(State(state): State<Arc<AppState>>) -> Response {
        let oauth_config = match &state.oauth_config {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, "OAuth not configured").into_response(),
        };
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
        let oauth_config = match &state.oauth_config {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, "OAuth not configured").into_response(),
        };

        // Phase 1-2: client_id is required and must be registered.
        let client_id = match params.get("client_id") {
            Some(id) => id.clone(),
            None => {
                return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", "Missing client_id");
            }
        };
        {
            let store = state.token_store.lock().await;
            let client = match store.registered_clients.get(&client_id) {
                Some(c) => c.clone(),
                None => {
                    return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_client", "Unknown client_id");
                }
            };

            // Phase 1-2: redirect_uri must be registered.
            let redirect_uri_param = params.get("redirect_uri");
            match redirect_uri_param {
                Some(uri) if !client.redirect_uris.contains(uri) => {
                    return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri not registered for this client");
                }
                None if client.redirect_uris.is_empty() => {
                    return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", "Missing redirect_uri and no default registered");
                }
                _ => {}
            }
        }

        let redirect_uri = match params.get("redirect_uri") {
            Some(u) => u.clone(),
            None => {
                let store = state.token_store.lock().await;
                let client = store.registered_clients.get(&client_id).unwrap();
                client.redirect_uris[0].clone()
            }
        };

        // Phase 1-1: PKCE is required, S256 only.
        let code_challenge = match params.get("code_challenge") {
            Some(c) => c.clone(),
            None => {
                return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", "code_challenge is required (PKCE)");
            }
        };
        let code_challenge_method = params
            .get("code_challenge_method")
            .cloned()
            .unwrap_or_else(|| "S256".to_string());
        if code_challenge_method != "S256" {
            return oauth_error_response(StatusCode::BAD_REQUEST, "invalid_request", "Only S256 code_challenge_method is supported");
        }

        let client_state = params.get("state").cloned();

        // Generate our own state for the Google OAuth redirect.
        let our_state = oauth::generate_secure_token();

        {
            let mut store = state.token_store.lock().await;
            // Phase 2-11: cleanup and check capacity.
            store.cleanup_expired();
            if store.is_pending_auths_full() {
                return oauth_error_response(StatusCode::SERVICE_UNAVAILABLE, "server_error", "Too many pending authorizations");
            }
            store.pending_auths.insert(
                our_state.clone(),
                oauth::PendingAuth {
                    client_redirect_uri: redirect_uri,
                    client_state,
                    code_challenge,
                    code_challenge_method,
                    client_id,
                    created_at: chrono::Utc::now().timestamp(),
                },
            );
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

    /// GET /oauth/callback — Google redirects here after user consent.
    async fn handle_oauth_callback(
        State(state): State<Arc<AppState>>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        let oauth_config = match &state.oauth_config {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, "OAuth not configured").into_response(),
        };

        let google_code = match params.get("code") {
            Some(c) => c.clone(),
            None => {
                let error = params.get("error").map(|s| s.as_str()).unwrap_or("unknown");
                return (
                    StatusCode::BAD_REQUEST,
                    format!("OAuth error: {error}"),
                )
                    .into_response();
            }
        };

        let our_state = match params.get("state") {
            Some(s) => s.clone(),
            None => return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response(),
        };

        // Look up pending auth and check TTL.
        let pending = {
            let mut store = state.token_store.lock().await;
            store.pending_auths.remove(&our_state)
        };

        let pending = match pending {
            Some(p) => {
                // Phase 2-2: pending_auths TTL check.
                if chrono::Utc::now().timestamp() - p.created_at > oauth::PENDING_AUTH_TTL_SECS {
                    return (StatusCode::BAD_REQUEST, "Authorization request expired").into_response();
                }
                p
            }
            None => {
                return (StatusCode::BAD_REQUEST, "Unknown or expired state").into_response()
            }
        };

        // Exchange Google code for tokens.
        let google_tokens = match oauth::exchange_google_code(oauth_config, &google_code).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[gws mcp] Google token exchange failed: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Token exchange failed",
                )
                    .into_response();
            }
        };

        // Get user email from Google.
        let email = match oauth::get_google_userinfo(&google_tokens.access_token).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[gws mcp] Failed to get userinfo: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to identify user",
                )
                    .into_response();
            }
        };

        eprintln!("[gws mcp] OAuth callback: authenticated user {email}");

        // Generate our auth code for the client.
        let our_code = oauth::generate_secure_token();
        {
            let mut store = state.token_store.lock().await;
            store.cleanup_expired();
            if store.is_pending_codes_full() {
                return (StatusCode::SERVICE_UNAVAILABLE, "Too many pending codes").into_response();
            }
            store.pending_codes.insert(
                our_code.clone(),
                oauth::PendingCode {
                    session: oauth::UserSession {
                        email,
                        google_tokens,
                        bearer_expires_at: chrono::Utc::now().timestamp() + oauth::BEARER_TOKEN_LIFETIME_SECS,
                    },
                    code_challenge: pending.code_challenge,
                    code_challenge_method: pending.code_challenge_method,
                    created_at: chrono::Utc::now().timestamp(),
                },
            );
        }

        // Redirect back to the client with our auth code (url-encoded).
        let mut redirect = pending.client_redirect_uri;
        let sep = if redirect.contains('?') { "&" } else { "?" };
        let encoded_code = percent_encoding::utf8_percent_encode(
            &our_code,
            percent_encoding::NON_ALPHANUMERIC,
        );
        redirect.push_str(&format!("{sep}code={encoded_code}"));
        if let Some(cs) = &pending.client_state {
            redirect.push_str(&format!(
                "&state={}",
                percent_encoding::utf8_percent_encode(
                    cs,
                    percent_encoding::NON_ALPHANUMERIC,
                )
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
        let oauth_config = match &state.oauth_config {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, "OAuth not configured").into_response(),
        };

        // CORS headers for /token
        let cors_headers = build_cors_headers(&headers, &state.allowed_origins);

        // Parse form-encoded body.
        let params: HashMap<String, String> =
            serde_urlencoded::from_str(&body).unwrap_or_default();

        let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");

        match grant_type {
            "authorization_code" => {
                handle_token_authorization_code(&state, &params, cors_headers).await
            }
            "refresh_token" => {
                handle_token_refresh(&state, oauth_config, &params, cors_headers).await
            }
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
        let code = match params.get("code") {
            Some(c) => c.clone(),
            None => {
                return token_error_response("invalid_request", "Missing code", cors_headers);
            }
        };

        // Take the pending code.
        let pending_code = {
            let mut store = state.token_store.lock().await;
            store.pending_codes.remove(&code)
        };

        let pending_code = match pending_code {
            Some(pc) => {
                // Phase 2-1: auth code TTL check (10 minutes).
                if chrono::Utc::now().timestamp() - pc.created_at > oauth::AUTH_CODE_TTL_SECS {
                    return token_error_response("invalid_grant", "Authorization code expired", cors_headers);
                }
                pc
            }
            None => {
                return token_error_response("invalid_grant", "Invalid authorization code", cors_headers);
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

        // Issue bearer token with 256-bit entropy.
        let bearer_token = oauth::generate_secure_token();
        let expires_in = oauth::BEARER_TOKEN_LIFETIME_SECS;
        {
            let mut store = state.token_store.lock().await;
            store.cleanup_expired();
            if store.is_bearer_sessions_full() {
                return token_error_response("server_error", "Too many active sessions", cors_headers);
            }
            store
                .bearer_sessions
                .insert(bearer_token.clone(), pending_code.session);
        }

        let mut resp_headers = cors_headers;
        resp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let resp_body = json!({
            "access_token": bearer_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
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
        let old_bearer = match params.get("refresh_token") {
            Some(t) => t.clone(),
            None => {
                return token_error_response("invalid_request", "Missing refresh_token", cors_headers);
            }
        };

        // Look up the existing session.
        let session = {
            let mut store = state.token_store.lock().await;
            store.bearer_sessions.remove(&old_bearer)
        };

        let mut session = match session {
            Some(s) => s,
            None => {
                return token_error_response("invalid_grant", "Unknown refresh token", cors_headers);
            }
        };

        // Refresh Google token if needed.
        if session.google_tokens.is_expired() {
            let rt = match &session.google_tokens.refresh_token {
                Some(rt) => rt.clone(),
                None => {
                    return token_error_response("invalid_grant", "No Google refresh token available", cors_headers);
                }
            };
            match oauth::refresh_google_token(oauth_config, &rt).await {
                Ok(new_tokens) => session.google_tokens = new_tokens,
                Err(_) => {
                    return token_error_response("invalid_grant", "Failed to refresh Google token", cors_headers);
                }
            }
        }

        // Issue new bearer token.
        let new_bearer = oauth::generate_secure_token();
        let expires_in = oauth::BEARER_TOKEN_LIFETIME_SECS;
        session.bearer_expires_at = chrono::Utc::now().timestamp() + expires_in;

        {
            let mut store = state.token_store.lock().await;
            store.cleanup_expired();
            if store.is_bearer_sessions_full() {
                return token_error_response("server_error", "Too many active sessions", cors_headers);
            }
            store.bearer_sessions.insert(new_bearer.clone(), session);
        }

        let mut resp_headers = cors_headers;
        resp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let resp_body = json!({
            "access_token": new_bearer,
            "token_type": "Bearer",
            "expires_in": expires_in,
        });

        (
            StatusCode::OK,
            resp_headers,
            serde_json::to_string(&resp_body).unwrap(),
        )
            .into_response()
    }

    fn token_error_response(error: &str, description: &str, cors_headers: HeaderMap) -> Response {
        let mut resp_headers = cors_headers;
        resp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        (
            StatusCode::BAD_REQUEST,
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
        if state.oauth_config.is_none() {
            return (StatusCode::NOT_FOUND, "OAuth not configured").into_response();
        }

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
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Invalid registration request").into_response()
            }
        };

        // Phase 2-3: validate redirect_uri schemes.
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
        let client = oauth::RegisteredClient {
            client_id: client_id.clone(),
            redirect_uris: req.redirect_uris.clone(),
            client_name: req.client_name.clone(),
            client_id_issued_at: now,
        };

        {
            let mut store = state.token_store.lock().await;
            if store.is_registered_clients_full() {
                return (StatusCode::SERVICE_UNAVAILABLE, "Too many registered clients").into_response();
            }
            store
                .registered_clients
                .insert(client_id.clone(), client);
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

    /// Build CORS response headers for OAuth endpoints.
    fn build_cors_headers(req_headers: &HeaderMap, allowed_origins: &[String]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(origin) = req_headers.get("origin").and_then(|v| v.to_str().ok()) {
            let allowed = if allowed_origins.is_empty() {
                let lower = origin.to_lowercase();
                lower.starts_with("http://localhost")
                    || lower.starts_with("https://localhost")
                    || lower.starts_with("http://127.0.0.1")
                    || lower.starts_with("https://127.0.0.1")
                    || lower.starts_with("http://[::1]")
                    || lower.starts_with("https://[::1]")
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

        fn test_state() -> Arc<AppState> {
            test_state_with_origins(vec![])
        }

        fn test_state_with_origins(allowed_origins: Vec<String>) -> Arc<AppState> {
            Arc::new(AppState {
                config: ServerConfig {
                    services: vec![],
                    workflows: false,
                    _helpers: false,
                },
                tools_cache: Mutex::new(None),
                sessions: Mutex::new(HashMap::new()),
                allowed_origins,
                oauth_config: None,
                token_store: Mutex::new(TokenStore::new()),
            })
        }

        fn test_state_with_oauth() -> Arc<AppState> {
            Arc::new(AppState {
                config: ServerConfig {
                    services: vec![],
                    workflows: false,
                    _helpers: false,
                },
                tools_cache: Mutex::new(None),
                sessions: Mutex::new(HashMap::new()),
                allowed_origins: vec![],
                oauth_config: Some(OAuthConfig {
                    client_id: "test-client-id".to_string(),
                    client_secret: "test-secret".to_string(),
                    base_url: "https://gw.example.com".to_string(),
                    scopes: "openid email".to_string(),
                }),
                token_store: Mutex::new(TokenStore::new()),
            })
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
                .route("/token", post(handle_token))
                .route("/register", post(handle_register))
                .with_state(state)
        }

        async fn init_session(app: &Router) -> String {
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

        // --- Existing MCP transport tests (no OAuth) ---

        #[tokio::test]
        async fn test_initialize_returns_session_id() {
            let state = test_state();
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

            assert_eq!(resp.status(), StatusCode::OK);
            assert!(resp.headers().get("mcp-session-id").is_some());
            let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let result: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(result["result"]["protocolVersion"], "2024-11-05");
        }

        #[tokio::test]
        async fn test_tools_list_requires_session() {
            let state = test_state();
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
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
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_tools_list_with_valid_session() {
            let state = test_state();
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
            let state = test_state();
            let app = test_app(state);
            let session_id = init_session(&app).await;
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .header("mcp-session-id", &session_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            let body = json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_notification_returns_accepted() {
            let state = test_state();
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
            let state = test_state();
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
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
            let state = test_state();
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_delete_unknown_session() {
            let state = test_state();
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .header("mcp-session-id", "nonexistent")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_invalid_session_returns_not_found() {
            let state = test_state();
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", "does-not-exist")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_batch_request() {
            let state = test_state();
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
            let state = test_state();
            let app = test_app(state);
            let session_id = init_session(&app).await;
            let batch =
                json!([{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}]);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
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
            let state = test_state();
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
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
            let state = test_state();
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
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
            let state =
                test_state_with_origins(vec!["https://my-app.example.com".to_string()]);
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
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
            let state = test_state();
            let app = test_app(state);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
        }

        #[tokio::test]
        async fn test_get_requires_accept_event_stream() {
            let state = test_state();
            let app = test_app(state);
            let session_id = init_session(&app).await;
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/mcp")
                        .header("accept", "application/json")
                        .header("mcp-session-id", &session_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
        }

        #[tokio::test]
        async fn test_get_invalid_session_returns_not_found() {
            let state = test_state();
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/mcp")
                        .header("accept", "text/event-stream")
                        .header("mcp-session-id", "does-not-exist")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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

        fn make_pending_code(challenge: String) -> oauth::PendingCode {
            oauth::PendingCode {
                session: oauth::UserSession {
                    email: "user@test.com".to_string(),
                    google_tokens: oauth::GoogleTokens {
                        access_token: "google-at".to_string(),
                        refresh_token: Some("google-rt".to_string()),
                        expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                    },
                    bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
                },
                code_challenge: challenge,
                code_challenge_method: "S256".to_string(),
                created_at: chrono::Utc::now().timestamp(),
            }
        }

        fn make_bearer_session() -> oauth::UserSession {
            oauth::UserSession {
                email: "user@corp.com".to_string(),
                google_tokens: oauth::GoogleTokens {
                    access_token: "google-at".to_string(),
                    refresh_token: None,
                    expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                },
                bearer_expires_at: chrono::Utc::now().timestamp() + 86400,
            }
        }

        #[tokio::test]
        async fn test_oauth_metadata_returns_endpoints() {
            let state = test_state_with_oauth();
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
            assert_eq!(meta["authorization_endpoint"], "https://gw.example.com/authorize");
            assert_eq!(meta["token_endpoint"], "https://gw.example.com/token");
            // Phase 3-1: scopes_supported
            assert!(meta["scopes_supported"].is_array());
            // Phase 2-7: refresh_token in grant_types
            let grant_types = meta["grant_types_supported"].as_array().unwrap();
            assert!(grant_types.contains(&json!("refresh_token")));
        }

        #[tokio::test]
        async fn test_oauth_metadata_not_found_without_config() {
            let state = test_state();
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
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_authorize_requires_client_id() {
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
            let app = test_app(state.clone());
            let client_id = register_client(&app, &["https://x.com/cb"]).await;
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(&format!("/authorize?client_id={client_id}&redirect_uri=https://x.com/cb"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(body["error_description"].as_str().unwrap().contains("code_challenge"));
        }

        #[tokio::test]
        async fn test_authorize_rejects_plain_pkce() {
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from("grant_type=authorization_code&code=bogus&code_verifier=x"))
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
            let state = test_state_with_oauth();
            let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            let challenge = {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(verifier.as_bytes());
                oauth::base64_url_encode(&digest)
            };

            {
                let mut store = state.token_store.lock().await;
                store.pending_codes.insert("test-code".to_string(), make_pending_code(challenge));
            }

            let app = test_app(state.clone());
            let body_str = format!("grant_type=authorization_code&code=test-code&code_verifier={verifier}");
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
            // Phase 1-5: token_type is "Bearer" (capital B) and expires_in is present
            assert_eq!(result["token_type"], "Bearer");
            assert!(result["expires_in"].as_i64().unwrap() > 0);
            assert!(result["access_token"].as_str().is_some());

            let bearer = result["access_token"].as_str().unwrap();
            let store = state.token_store.lock().await;
            let session = store.bearer_sessions.get(bearer).unwrap();
            assert_eq!(session.email, "user@test.com");
        }

        #[tokio::test]
        async fn test_token_exchange_expired_code() {
            let state = test_state_with_oauth();
            let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            let challenge = {
                use sha2::Digest;
                let digest = sha2::Sha256::digest(verifier.as_bytes());
                oauth::base64_url_encode(&digest)
            };
            {
                let mut store = state.token_store.lock().await;
                let mut pc = make_pending_code(challenge);
                pc.created_at = chrono::Utc::now().timestamp() - 700; // expired (>600s)
                store.pending_codes.insert("expired-code".to_string(), pc);
            }
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(format!("grant_type=authorization_code&code=expired-code&code_verifier={verifier}")))
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
            let state = test_state_with_oauth();
            {
                let mut store = state.token_store.lock().await;
                store.pending_codes.insert(
                    "code2".to_string(),
                    make_pending_code("expected-challenge".to_string()),
                );
            }
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/token")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from("grant_type=authorization_code&code=code2&code_verifier=wrong"))
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
        async fn test_register_returns_client_id() {
            let state = test_state_with_oauth();
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
            // Phase 3-2: client_id_issued_at
            assert!(result["client_id_issued_at"].as_i64().is_some());
        }

        #[tokio::test]
        async fn test_register_rejects_dangerous_redirect_uri() {
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
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
            // Phase 2-6: WWW-Authenticate header present on 401
            assert!(resp.headers().get("www-authenticate").is_some());
            // Phase 2-5: absolute URL in resource_metadata
            let www_auth = resp.headers().get("www-authenticate").unwrap().to_str().unwrap();
            assert!(www_auth.contains("https://gw.example.com/.well-known/oauth-authorization-server"));
        }

        #[tokio::test]
        async fn test_mcp_post_with_valid_bearer_token() {
            let state = test_state_with_oauth();
            {
                let mut store = state.token_store.lock().await;
                store.bearer_sessions.insert("valid-bearer".to_string(), make_bearer_session());
            }
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
            let state = test_state_with_oauth();
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
            let state = test_state_with_oauth();
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
        async fn test_session_bearer_binding_rejects_wrong_bearer() {
            let state = test_state_with_oauth();
            // Register two bearer tokens.
            {
                let mut store = state.token_store.lock().await;
                store
                    .bearer_sessions
                    .insert("bearer-a".to_string(), make_bearer_session());
                store
                    .bearer_sessions
                    .insert("bearer-b".to_string(), make_bearer_session());
            }
            // Create a session with bearer-a via initialize.
            let app = test_app(state.clone());
            let body = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("authorization", "Bearer bearer-a")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let session_id = resp
                .headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            // bearer-b should be FORBIDDEN from using bearer-a's session.
            let app = test_app(state.clone());
            let body2 =
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}});
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("authorization", "Bearer bearer-b")
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&body2).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);

            // bearer-a should still work with its own session.
            let app = test_app(state);
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("authorization", "Bearer bearer-a")
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&body2).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_delete_mcp_requires_auth_when_oauth_enabled() {
            let state = test_state_with_oauth();
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
}

// --- Shared tool building logic ---

async fn build_tools_list(config: &ServerConfig) -> Result<Vec<Value>, GwsError> {
    let mut tools = Vec::new();

    for svc_name in &config.services {
        let (api_name, version) =
            crate::parse_service_and_version(std::slice::from_ref(svc_name), svc_name)?;
        if let Ok(doc) = crate::discovery::fetch_discovery_document(&api_name, &version).await {
            walk_resources(&doc.name, &doc.resources, &mut tools);
        } else {
            eprintln!("[gws mcp] Warning: Failed to load discovery document for service '{}'. It will not be available as a tool.", svc_name);
        }
    }

    if config.workflows {
        tools.push(json!({
            "name": "workflow_standup_report",
            "description": "Today's meetings + open tasks as a standup summary",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": { "type": "string", "description": "Output format: json, table, yaml, csv" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_meeting_prep",
            "description": "Prepare for your next meeting: agenda, attendees, and linked docs",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "calendar": { "type": "string", "description": "Calendar ID (default: primary)" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_email_to_task",
            "description": "Convert a Gmail message into a Google Tasks entry",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_id": { "type": "string", "description": "Gmail message ID" },
                    "tasklist": { "type": "string", "description": "Task list ID" }
                },
                "required": ["message_id"]
            }
        }));
        tools.push(json!({
            "name": "workflow_weekly_digest",
            "description": "Weekly summary: this week's meetings + unread email count",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": { "type": "string", "description": "Output format" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_file_announce",
            "description": "Announce a Drive file in a Chat space",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": { "type": "string", "description": "Drive file ID" },
                    "space": { "type": "string", "description": "Chat space name" },
                    "message": { "type": "string", "description": "Custom message" }
                },
                "required": ["file_id", "space"]
            }
        }));
    }

    Ok(tools)
}

fn walk_resources(prefix: &str, resources: &HashMap<String, RestResource>, tools: &mut Vec<Value>) {
    for (res_name, res) in resources {
        let new_prefix = format!("{}_{}", prefix, res_name);

        for (method_name, method) in &res.methods {
            let tool_name = format!("{}_{}", new_prefix, method_name);
            let mut description = method.description.clone().unwrap_or_default();
            if description.is_empty() {
                description = format!("Execute the {} Google API method", tool_name);
            }

            let input_schema = json!({
                "type": "object",
                "properties": {
                    "params": {
                        "type": "object",
                        "description": "Query or path parameters (e.g. fileId, q, pageSize)"
                    },
                    "body": {
                        "type": "object",
                        "description": "Request body API object"
                    },
                    "upload": {
                        "type": "string",
                        "description": "Local file path to upload as media content"
                    },
                    "page_all": {
                        "type": "boolean",
                        "description": "Auto-paginate, returning all pages"
                    }
                }
            });

            tools.push(json!({
                "name": tool_name,
                "description": description,
                "inputSchema": input_schema
            }));
        }

        if !res.resources.is_empty() {
            walk_resources(&new_prefix, &res.resources, tools);
        }
    }
}

async fn handle_tools_call(
    params: &Value,
    config: &ServerConfig,
    access_token: Option<&str>,
) -> Result<Value, GwsError> {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| GwsError::Validation("Missing 'name' in tools/call".to_string()))?;

    let default_args = json!({});
    let arguments = params.get("arguments").unwrap_or(&default_args);

    if tool_name.starts_with("workflow_") {
        return Err(GwsError::Other(anyhow::anyhow!(
            "Workflows are not yet fully implemented via MCP"
        )));
    }

    let parts: Vec<&str> = tool_name.split('_').collect();
    if parts.len() < 3 {
        return Err(GwsError::Validation(format!(
            "Invalid API tool name: {}",
            tool_name
        )));
    }

    let svc_alias = parts[0];

    if !config.services.contains(&svc_alias.to_string()) {
        return Err(GwsError::Validation(format!(
            "Service '{}' is not enabled in this MCP session",
            svc_alias
        )));
    }

    let (api_name, version) =
        crate::parse_service_and_version(&[svc_alias.to_string()], svc_alias)?;
    let doc = crate::discovery::fetch_discovery_document(&api_name, &version).await?;

    let mut current_resources = &doc.resources;
    let mut current_res = None;

    for res_name in &parts[1..parts.len() - 1] {
        if let Some(res) = current_resources.get(*res_name) {
            current_res = Some(res);
            current_resources = &res.resources;
        } else {
            return Err(GwsError::Validation(format!(
                "Resource '{}' not found in Discovery Document",
                res_name
            )));
        }
    }

    let method_name = parts.last().unwrap();
    let method = if let Some(res) = current_res {
        res.methods
            .get(*method_name)
            .ok_or_else(|| GwsError::Validation(format!("Method '{}' not found", method_name)))?
    } else {
        return Err(GwsError::Validation("Resource not found".to_string()));
    };

    let params_json_val = arguments.get("params");
    let params_str = params_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize params: {e}")))?;

    let body_json_val = arguments.get("body");
    let body_str = body_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize body: {e}")))?;

    // Security: validate upload path to prevent arbitrary local file reads.
    let upload_path = if let Some(raw) = arguments.get("upload").and_then(|v| v.as_str()) {
        let p = std::path::Path::new(raw);
        if p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir) {
            return Err(GwsError::Validation(format!(
                "Upload path '{}' is not allowed. Paths must be relative and within the current directory.",
                raw
            )));
        }
        Some(raw)
    } else {
        None
    };
    let page_all = arguments
        .get("page_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let pagination = crate::executor::PaginationConfig {
        page_all,
        page_limit: 100,
        page_delay_ms: 100,
    };

    let scopes: Vec<&str> = method.scopes.iter().map(|s| s.as_str()).collect();
    let (token, auth_method) = if let Some(tok) = access_token {
        // Gateway mode: use the pre-authenticated user's Google token.
        (Some(tok.to_string()), crate::executor::AuthMethod::OAuth)
    } else {
        // Local mode: use local credentials.
        match crate::auth::get_token(&scopes, None).await {
            Ok(t) => (Some(t), crate::executor::AuthMethod::OAuth),
            Err(e) => {
                eprintln!(
                    "[gws mcp] Warning: Authentication failed, proceeding without credentials: {e}"
                );
                (None, crate::executor::AuthMethod::None)
            }
        }
    };

    let result = crate::executor::execute_method(
        &doc,
        method,
        params_str.as_deref(),
        body_str.as_deref(),
        token.as_deref(),
        auth_method,
        None,
        upload_path,
        false,
        &pagination,
        None,
        &crate::helpers::modelarmor::SanitizeMode::Warn,
        &crate::formatter::OutputFormat::default(),
        true,
    )
    .await?;

    let text_content = match result {
        Some(val) => serde_json::to_string_pretty(&val).unwrap_or_else(|_| "[]".to_string()),
        None => "Execution completed with no output.".to_string(),
    };

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text_content
            }
        ],
        "isError": false
    }))
}
